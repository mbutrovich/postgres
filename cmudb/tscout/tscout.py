#!/usr/bin/python3
import argparse
import logging
import multiprocessing as mp
import os
import re
import sys
import time
from dataclasses import dataclass
from distutils import util
from enum import Enum, auto, unique

import model
import psutil
import psycopg
import setproctitle
from bcc import (  # pylint: disable=no-name-in-module
    BPF,
    USDT,
    PerfHWConfig,
    PerfType,
    utils,
)
from psycopg.rows import dict_row


@dataclass
class PostgresInstance:
    """Finds and then stashes the PIDs for a postgres instance designated by the constructor's pid argument."""

    def __init__(self, pid):
        def cmd_in_cmdline(cmd, proc):
            """

            Parameters
            ----------
            cmd: str
            proc: psutil.Process

            Returns
            -------
            True if the provided command was in the provided Process' command line args.
            """
            return any(cmd in x for x in proc.cmdline())

        self.postgres_pid = pid
        try:
            # Iterate through all the children for the given PID, and extract PIDs for expected background workers.
            for child in psutil.Process(self.postgres_pid).children():
                if not self.checkpointer_pid and cmd_in_cmdline("checkpointer", child):
                    self.checkpointer_pid = child.pid
                elif not self.bgwriter_pid and cmd_in_cmdline("background", child) and cmd_in_cmdline("writer", child):
                    self.bgwriter_pid = child.pid
                elif not self.walwriter_pid and cmd_in_cmdline("walwriter", child):
                    self.walwriter_pid = child.pid
                elif all(x is not None for x in [self.checkpointer_pid, self.bgwriter_pid, self.walwriter_pid]):
                    # We found all the children PIDs that we care about, so we're done.
                    return
        except psutil.NoSuchProcess:
            logger.error("Provided PID not found.")
            sys.exit(1)

        if any(x is None for x in [self.checkpointer_pid, self.bgwriter_pid, self.walwriter_pid]):
            # TODO(Matt): maybe get fancy with dataclasses.fields() so we don't have to keep adding to this if more
            #  fields are added to the dataclass?
            logger.error("Did not find expected background workers for provided PID.")
            sys.exit(1)

    postgres_pid: int = None
    checkpointer_pid: int = None
    bgwriter_pid: int = None
    walwriter_pid: int = None


logger = logging.getLogger("tscout")

# Set up the OUs and metrics to be collected.
modeler = model.Model()
operating_units = modeler.operating_units
metrics = modeler.metrics

# OUs may have common structs that cause duplicate struct definitions in
# the collector_c file that is generated, e.g., struct Plan.
# helper_struct_defs is used to avoid duplicate struct definitions by
# accumulating all the struct definitions exactly once, and defining those
# structs at one shot at the start of the generated collector_c file.
HELPER_STRUCT_DEFS = {}


def generate_readargs(feature_list):
    """
    Generate bpf_usdt_readargs_p() calls for the given feature list.

    This function assumes that the following are in scope:
    - struct pt_regs *ctx
    - struct SUBST_OU_output *output

    Parameters
    ----------
    feature_list : List[model.Feature]
        List of BPF features being emitted.

    Returns
    -------
    code : str
        bpf_usdt_readarg() and bpf_usdt_readarg_p() invocations.
    """
    code = []
    non_feature_usdt_args = 1  # Currently just ou_instance. If any other non-feature args are added, increment this.
    for idx, feature in enumerate(feature_list, 1):
        first_member = feature.bpf_tuple[0].name
        if feature.readarg_p:
            readarg_p = [
                "  bpf_usdt_readarg_p(",
                f"{idx + non_feature_usdt_args}, ",
                "ctx, ",
                f"&(features->{first_member}), ",
                f"sizeof(struct DECL_{feature.name})",
                ");\n",
            ]
            code.append("".join(readarg_p))
        else:
            readarg = [
                "  bpf_usdt_readarg(",
                f"{idx + non_feature_usdt_args}, ",
                "ctx, ",
                f"&(features->{first_member})",
                ");\n",
            ]
            code.append("".join(readarg))
    return "".join(code)


def generate_reagents(feature_list, reagents_used):
    code = []
    for feature in feature_list:
        for field in feature.bpf_tuple:
            if field.pg_type in model.REAGENTS:
                reagents_used.add(field.pg_type)
                code.append(model.REAGENTS[field.pg_type].produce_one_field(field.name))
    return "".join(code)


def generate_markers(operation, ou_index, reagents_used):
    # pylint: disable=global-statement
    global HELPER_STRUCT_DEFS
    # Load the C code for the Markers.
    with open("markers.c", "r", encoding="utf-8") as markers_file:
        markers_c = markers_file.read()

    # Replace OU-specific placeholders in C code.
    markers_c = markers_c.replace("SUBST_OU", f"{operation.function}")
    markers_c = markers_c.replace("SUBST_READARGS", generate_readargs(operation.features_list))
    # TODO(Matt): We're making multiple passes through the features_list. Maybe collapse generate_reagents and
    #  generate_readargs into one function.
    markers_c = markers_c.replace("SUBST_REAGENTS", generate_reagents(operation.features_list, reagents_used))
    markers_c = markers_c.replace("SUBST_FEATURES", operation.features_struct())
    markers_c = markers_c.replace("SUBST_INDEX", str(ou_index))
    markers_c = markers_c.replace("SUBST_FIRST_FEATURE", operation.features_list[0].bpf_tuple[0].name)

    # Accumulate struct definitions.
    HELPER_STRUCT_DEFS = {**HELPER_STRUCT_DEFS, **operation.helper_structs()}

    return markers_c


def collector(collector_flags, table_stats, ou_processor_queues, pid, socket_fd):
    setproctitle.setproctitle(f"{pid} TScout Collector")

    # Read the C code for the Collector.
    with open("collector.c", "r", encoding="utf-8") as collector_file:
        collector_c = collector_file.read()

    # Append the C code for the Probes.
    with open("probes.c", "r", encoding="utf-8") as probes_file:
        collector_c += probes_file.read()
    # Append the C code for the Markers. Accumulate the Reagents that we need into a set to use later to add the
    # definitions that we need.
    reagents_used = set()
    for ou_index, ou in enumerate(operating_units):
        collector_c += generate_markers(ou, ou_index, reagents_used)

    # Process the list of Reagents that we need. Prepend the C code for the Reagent functions, add struct declaration to
    # HELPER_STRUCT_DEFS to be prepended later.
    for reagent_used in reagents_used:
        reagent = model.REAGENTS[reagent_used]
        collector_c = reagent.reagent_fn() + "\n" + collector_c
        if reagent.type_name not in HELPER_STRUCT_DEFS:
            # We may already have a struct definition for this type if it was unrolled in a struct somewhere already.
            HELPER_STRUCT_DEFS[reagent.type_name] = model.struct_decl_for_fields(reagent.type_name, reagent.bpf_tuple)

    # Prepend the helper struct defs.
    collector_c = "\n".join(HELPER_STRUCT_DEFS.values()) + "\n" + collector_c

    # Replace placeholders related to metrics.
    defs = [f"{model.CLANG_TO_BPF[metric.c_type]} {metric.name}{metric.alignment_string()}" for metric in metrics]
    metrics_struct = ";\n".join(defs) + ";"
    collector_c = collector_c.replace("SUBST_METRICS", metrics_struct)
    accumulate = [
        f"lhs->{metric.name} += rhs->{metric.name}"
        for metric in metrics
        if metric.name not in ("start_time", "end_time", "pid", "cpu_id")
    ]  # don't accumulate these metrics
    metrics_accumulate = ";\n".join(accumulate) + ";"
    collector_c = collector_c.replace("SUBST_ACCUMULATE", metrics_accumulate)
    collector_c = collector_c.replace("SUBST_FIRST_METRIC", metrics[0].name)

    num_cpus = len(utils.get_online_cpus())
    collector_c = collector_c.replace("MAX_CPUS", str(num_cpus))

    # Attach USDT probes to the target PID.
    collector_probes = USDT(pid=pid)
    for ou in operating_units:
        for probe in [ou.features_marker(), ou.begin_marker(), ou.end_marker(), ou.flush_marker()]:
            collector_probes.enable_probe(probe=probe, fn_name=probe)

    # Load the BPF program, eliding setting the socket fd
    # if this pid won't generate network metrics.
    cflags = ['-DKBUILD_MODNAME="collector"']
    if socket_fd:
        cflags.append(f"-DCLIENT_SOCKET_FD={socket_fd}")

    collector_bpf = BPF(text=collector_c, usdt_contexts=[collector_probes], cflags=cflags)

    # open perf hardware events for BPF program
    collector_bpf["cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
    collector_bpf["instructions"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.INSTRUCTIONS)
    collector_bpf["cache_references"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CACHE_REFERENCES)
    collector_bpf["cache_misses"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CACHE_MISSES)
    collector_bpf["ref_cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.REF_CPU_CYCLES)

    lost_collector_events = 0

    def lost_collector_event(num_lost):
        nonlocal lost_collector_events
        lost_collector_events = lost_collector_events + num_lost

    def collector_event_builder(output_buffer):
        def collector_event(cpu, data, size):
            # pylint: disable=unused-argument
            raw_data = collector_bpf[output_buffer].event(data)
            operating_unit = operating_units[raw_data.ou_index]

            if operating_unit.name() in {
                "ExecBitmapHeapScan",
                "ExecBitmapIndexScan",
                "ExecIndexOnlyScan",
                "ExecIndexScan",
                "ExecModifyTable",
                "ExecSampleScan",
                "ExecSeqScan",
                "ExecTidRangeScan",
                "ExecTidScan",
            }:
                table_oid = str(raw_data.target_table_oid)
                # print(table_oid)
                target_table_stats = table_stats[table_oid] + ","
                # print(target_table_stats)
                event_features = target_table_stats + operating_unit.serialize_features(
                    raw_data
                )  # TODO(Matt): consider moving serialization to CSV string to Processor
            else:
                event_features = operating_unit.serialize_features(
                    raw_data
                )  # TODO(Matt): consider moving serialization to CSV string to Processor
            training_data = "".join(
                [event_features, ",", ",".join(metric.serialize(raw_data) for metric in metrics), "\n"]
            )
            ou_processor_queues[raw_data.ou_index].put(training_data)  # TODO(Matt): maybe put_nowait?

        return collector_event

    # Open an output buffer for this OU.
    for i in range(len(operating_units)):
        output_buffer = f"collector_results_{i}"
        collector_bpf[output_buffer].open_perf_buffer(
            callback=collector_event_builder(output_buffer), lost_cb=lost_collector_event
        )

    logger.info("Collector attached to PID %s.", pid)

    # Poll on the Collector's output buffer until Collector is shut down.
    while collector_flags[pid]:
        try:
            # Use a timeout to periodically check the flag
            # since polling the output buffer blocks.
            collector_bpf.perf_buffer_poll(1000)
        except KeyboardInterrupt:
            logger.info("Collector for PID %s caught KeyboardInterrupt.", pid)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Collector for PID %s caught %s.", pid, e)

    if lost_collector_events > 0:
        logger.warning("Collector for PID %s lost %s events.", pid, lost_collector_events)
    logger.info("Collector for PID %s shut down.", pid)


def lost_something(num_lost):
    # num_lost. pylint: disable=unused-argument
    pass


table_stats_query = "SELECT relid,n_tup_ins,n_tup_upd,n_tup_del,n_tup_hot_upd,n_live_tup,n_dead_tup,n_mod_since_analyze,n_ins_since_vacuum FROM pg_stat_user_tables;"


def settings_collector(table_stats, shutdown):
    @unique
    class SettingType(Enum):
        BOOLEAN = auto()
        INTEGER = auto()
        BYTES = auto()
        INTEGER_TIME = auto()
        FLOAT_TIME = auto()
        FLOAT = auto()
        ENUM = auto()

    def _time_unit_to_ms(str):
        if str == "d":
            return 1000 * 60 * 60 * 24
        elif str == "h":
            return 1000 * 60 * 60
        elif str == "min":
            return 1000 * 60
        elif str == "s":
            return 1000
        elif str == "ms":
            return 1
        elif str == "us":
            return 1.0 / 1000
        else:
            return None

    def _parse_field(type, value):
        if type == SettingType.BOOLEAN:
            return util.strtobool(value)
        elif type == SettingType.INTEGER:
            return int(value)
        elif type == SettingType.BYTES:
            if value in ["-1", "0"]:
                # Hardcoded default/disabled values for this field.
                return int(value)
            bytes_regex = re.compile(r"(\d+)\s*([kmgtp]?b)", re.IGNORECASE)
            order = ("b", "kb", "mb", "gb", "tb", "pb")
            field_bytes = None
            for number, unit in bytes_regex.findall(value):
                field_bytes = int(number) * (1024 ** order.index(unit.lower()))
            assert field_bytes is not None, f"Failed to parse bytes from value string {value}"
            return field_bytes
        elif type == SettingType.INTEGER_TIME:
            if value == "-1":
                # Hardcoded default/disabled values for this field.
                return int(value)
            bytes_regex = re.compile(r"(\d+)\s*((?:d|h|min|s|ms|us)?)", re.IGNORECASE)
            field_ms = None
            for number, unit in bytes_regex.findall(value):
                field_ms = int(number) * _time_unit_to_ms(unit)
            assert field_ms is not None, f"Failed to parse time from value string {value}"
            return field_ms
        elif type == SettingType.FLOAT_TIME:
            if value == "0":
                # Hardcoded default/disabled values for this field.
                return int(value)
            bytes_regex = re.compile(r"(\d+(?:\.\d+)?)\s*((?:d|h|min|s|ms|us)?)", re.IGNORECASE)
            field_ms = None
            for number, unit in bytes_regex.findall(value):
                field_ms = float(number) * _time_unit_to_ms(unit)
            assert field_ms is not None, f"Failed to parse time from value string {value}"
            return field_ms
        elif type == SettingType.FLOAT:
            return float(value)
        else:
            return None

    def scrape_settings(connection, rows):
        result = {}
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("SHOW ALL;")
            for record in cursor:
                setting_name = record["name"]
                if setting_name in rows:
                    setting_type = rows[setting_name]
                    setting_str = record["setting"]
                    result[setting_name] = _parse_field(setting_type, setting_str)

        connection.commit()
        return result

    def scrape_table(connection, query):
        # Open a cursor to perform database operations
        tuples = []
        columns = []
        with connection.cursor() as cursor:
            # Query the database and obtain data as Python objects.
            cursor.execute(query)
            for column in cursor.description:
                columns.append(column.name)
            for record in cursor:
                tuples.append(record)

        connection.commit()
        return columns, tuples

    autovac_knobs = {
        # https://www.postgresql.org/docs/current/runtime-config-autovacuum.html
        "autovacuum": SettingType.BOOLEAN,
        "autovacuum_max_workers": SettingType.INTEGER,
        "autovacuum_naptime": SettingType.INTEGER_TIME,
        "autovacuum_vacuum_threshold": SettingType.INTEGER,
        "autovacuum_vacuum_insert_threshold": SettingType.INTEGER,
        "autovacuum_analyze_threshold": SettingType.INTEGER,
        "autovacuum_vacuum_scale_factor": SettingType.FLOAT,
        "autovacuum_vacuum_insert_scale_factor": SettingType.FLOAT,
        "autovacuum_analyze_scale_factor": SettingType.FLOAT,
        "autovacuum_freeze_max_age": SettingType.INTEGER,
        "autovacuum_multixact_freeze_max_age": SettingType.INTEGER,
        "autovacuum_vacuum_cost_delay": SettingType.FLOAT_TIME,
        "autovacuum_vacuum_cost_limit": SettingType.INTEGER,
        # https://www.postgresql.org/docs/12/runtime-config-resource.html
        "maintenance_work_mem": SettingType.BYTES,
        "autovacuum_work_mem": SettingType.BYTES,
        "vacuum_cost_delay": SettingType.FLOAT_TIME,
        "vacuum_cost_page_hit": SettingType.INTEGER,
        "vacuum_cost_page_miss": SettingType.INTEGER,
        "vacuum_cost_page_dirty": SettingType.INTEGER,
        "vacuum_cost_limit": SettingType.INTEGER,
        "effective_io_concurrency": SettingType.INTEGER,
        "maintenance_io_concurrency": SettingType.INTEGER,
        "max_worker_processes": SettingType.INTEGER,
        "max_parallel_workers_per_gather": SettingType.INTEGER,
        "max_parallel_maintenance_workers": SettingType.INTEGER,
        "max_parallel_workers": SettingType.INTEGER,
    }

    setproctitle.setproctitle("TScout Userspace Collector")

    with psycopg.connect("host=localhost port=5432 dbname=test user=matt", autocommit=True) as connection:
        # Poll on the Collector's output buffer until Collector is shut down.
        while not shutdown.is_set():
            try:
                # print(table_stats_columns)
                # print(table_stats)
                # results = scrape_settings(connection, autovac_knobs)
                # for setting_name, setting_value in results.items():
                #     print(setting_name, setting_value)
                _, tuples = scrape_table(connection, table_stats_query)
                # table_stats_columns = ",".join(str(val) for val in columns[1:])
                for row in tuples:
                    table_id = str(row[0])
                    table_stats[table_id] = ",".join(str(val) for val in row[1:])
                time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Userspace Collector caught KeyboardInterrupt.")
            except Exception as e:  # pylint: disable=broad-except
                # TODO(Matt): If postgres shuts down the connection closes and we get an exception for that.
                logger.warning("Userspace Collector caught %s.", e)

    logger.info("Userspace Collector shut down.")


def processor(ou, buffered_strings, outdir, append):
    setproctitle.setproctitle(f"TScout Processor {ou.name()}")

    file_path = f"{outdir}/{ou.name()}.csv"

    file_mode = "w"
    if append and os.path.exists(file_path):
        file_mode = "a"
    elif append:
        logger.warning("--append specified but %s does not exist. Creating this file instead.", file_path)

    # Open output file, with the name based on the OU.
    with open(file_path, mode=file_mode, encoding="utf-8") as file:
        if file_mode == "w":
            if ou.name() in {
                "ExecBitmapHeapScan",
                "ExecBitmapIndexScan",
                "ExecIndexOnlyScan",
                "ExecIndexScan",
                "ExecModifyTable",
                "ExecSampleScan",
                "ExecSeqScan",
                "ExecTidRangeScan",
                "ExecTidScan",
            }:
                file.write(
                    "n_tup_ins,n_tup_upd,n_tup_del,n_tup_hot_upd,n_live_tup,n_dead_tup,n_mod_since_analyze,n_ins_since_vacuum,"
                )
            # Write the OU's feature columns for CSV header,
            # with an additional separator before resource metrics columns.
            file.write(ou.features_columns() + ",")

            # Write the resource metrics columns for the CSV header.
            file.write(",".join(metric.name for metric in metrics) + "\n")

        logger.info("Processor started for %s.", ou.name())

        try:
            # Write serialized training data points from shared queue to file.
            while True:
                string = buffered_strings.get()
                file.write(string)

        except KeyboardInterrupt:
            logger.info("Processor for %s caught KeyboardInterrupt.", ou.name())
            while True:
                # TScout is shutting down.
                # Write any remaining training data points.
                string = buffered_strings.get()
                if string is None:
                    # Collectors have all shut down, and poison pill
                    # indicates there are no more training data points.
                    logger.info("Processor for %s received poison pill.", ou.name())
                    break
                file.write(string)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Processor for %s caught %s", ou.name(), e)
        finally:
            logger.info("Processor for %s shut down.", ou.name())


def main():
    parser = argparse.ArgumentParser(description="TScout")
    parser.add_argument("pid", type=int, help="Postmaster PID that we're attaching to")
    parser.add_argument("--outdir", required=False, default=".", help="Training data output directory")
    parser.add_argument(
        "--append",
        required=False,
        default=False,
        action="store_true",
        help="Append to training data in output directory",
    )
    args = parser.parse_args()
    pid = args.pid
    outdir = args.outdir
    append = args.append

    postgres = PostgresInstance(pid)

    setproctitle.setproctitle(f"{postgres.postgres_pid} TScout Coordinator")

    # Read the C code for TScout.
    with open("tscout.c", "r", encoding="utf-8") as tscout_file:
        tscout_c = tscout_file.read()

    # Attach USDT probes to the target PID.
    tscout_probes = USDT(pid=postgres.postgres_pid)
    for probe in ["fork_backend", "fork_background", "reap_backend", "reap_background"]:
        tscout_probes.enable_probe(probe=probe, fn_name=probe)

    # Load TScout program to monitor the Postmaster.
    tscout_bpf = BPF(text=tscout_c, usdt_contexts=[tscout_probes], cflags=['-DKBUILD_MODNAME="tscout"'])

    keep_running = True

    with mp.Manager() as manager:
        # Create coordination data structures for Collectors and Processors
        collector_flags = manager.dict()
        collector_processes = {}

        ou_processor_queues = []
        ou_processors = []

        table_stats = manager.dict()

        # Create a Processor for each OU
        for ou in operating_units:
            # TODO(Matt): maybe bound this queue size?
            #  may not work reliably with a poison pill for shutdown
            ou_processor_queue = mp.Queue()
            ou_processor_queues.append(ou_processor_queue)
            ou_processor = mp.Process(
                target=processor,
                args=(ou, ou_processor_queue, outdir, append),
            )
            ou_processor.start()
            ou_processors.append(ou_processor)

        shutdown = manager.Event()
        userspace_collector_process = mp.Process(
            target=settings_collector,
            args=(
                table_stats,
                shutdown,
            ),
        )
        userspace_collector_process.start()

        time.sleep(5)

        def create_collector(child_pid, socket_fd=None):
            logger.info("Postmaster forked PID %s, creating its Collector.", child_pid)
            collector_flags[child_pid] = True
            collector_process = mp.Process(
                target=collector, args=(collector_flags, table_stats, ou_processor_queues, child_pid, socket_fd)
            )
            collector_process.start()
            collector_processes[child_pid] = collector_process

        def destroy_collector(collector_process, child_pid):
            logger.info("Postmaster reaped PID %s, destroying its Collector.", child_pid)
            collector_flags[child_pid] = False
            collector_process.join()
            del collector_flags[child_pid]
            del collector_processes[child_pid]

        def postmaster_event(cpu, data, size):
            # cpu, size. pylint: disable=unused-argument
            output_event = tscout_bpf["postmaster_events"].event(data)
            event_type = output_event.type_
            child_pid = output_event.pid_
            if event_type in [0, 1]:
                fd = output_event.socket_fd_ if event_type == 0 else None
                create_collector(child_pid, fd)
            elif event_type in [2, 3]:
                collector_process = collector_processes.get(child_pid)
                if collector_process:
                    destroy_collector(collector_process, child_pid)
            else:
                logger.error("Unknown event type from Postmaster.")
                raise KeyboardInterrupt

        tscout_bpf["postmaster_events"].open_perf_buffer(callback=postmaster_event, lost_cb=lost_something)

        print(f"TScout attached to PID {postgres.postgres_pid}.")

        # Poll on TScout's output buffer until TScout is shut down.
        while keep_running:
            try:
                tscout_bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                keep_running = False
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("TScout caught %s.", e)

        print("TScout shutting down.")

        # Shut down the Collectors so that
        # no more data is generated for the Processors.
        shutdown.set()
        userspace_collector_process.join()
        for pid, _ in collector_processes.items():
            collector_flags[pid] = False
        for _, process in collector_processes.items():
            process.join()
            logger.info("Joined Collector for PID %s.", pid)
        print("TScout joined all Collectors.")

        # Shut down the Processor queues so that
        # everything gets flushed to the Processors.
        for ou_processor_queue in ou_processor_queues:
            ou_processor_queue.put(None)
            ou_processor_queue.close()
        for ou_processor_queue in ou_processor_queues:
            ou_processor_queue.join_thread()
        print("TScout joined all Processor queues.")

        # Shut down the Processors once the Processors are done
        # writing any remaining data to disk.
        for ou_processor in ou_processors:
            ou_processor.join()
        print("TScout joined all Processors.")
        print(f"TScout for PID {postgres.postgres_pid} shut down.")
        # We're done.
        sys.exit()


if __name__ == "__main__":
    main()
