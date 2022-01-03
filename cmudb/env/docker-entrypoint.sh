#!/bin/bash

# =====================================================================
# Environment variables.
# =====================================================================

# From the official PostgreSQL Docker image.
# https://hub.docker.com/_/postgres/

POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_INITDB_ARGS=${POSTGRES_INITDB_ARGS}
POSTGRES_INITDB_WALDIR=${POSTGRES_INITDB_WALDIR}
POSTGRES_HOST_AUTH_METHOD=${POSTGRES_HOST_AUTH_METHOD}
PGDATA=${PGDATA}

# The section below lists custom variables for our project.

# General purpose.
BIN_DIR=${BIN_DIR}  # Folder containing all the PostgreSQL binaries.
PGPORT=${PGPORT}    # The port to listen on.

# Replication.
NP_REPLICATION_TYPE=${NP_REPLICATION_TYPE}          # Must be "primary" or "replica"
NP_REPLICATION_USER=${NP_REPLICATION_USER}          # Replication user.
NP_REPLICATION_PASSWORD=${NP_REPLICATION_PASSWORD}  # Replication password.
NP_WAL_LEVEL=${NP_WAL_LEVEL}                        # The wal_level setting in PostgreSQL.

# The primary must have these defined.
NP_REPLICATION_PHYSICAL_SLOTS=${NP_REPLICATION_PHYSICAL_SLOTS}

# These settings need to be defined on ALL replicas.
NP_PRIMARY_NAME=${NP_PRIMARY_NAME}                  # The name of the primary on the Docker instance.
NP_PRIMARY_USERNAME=${NP_PRIMARY_USERNAME}          # The username to connect to the primary.
NP_PRIMARY_PORT=${NP_PRIMARY_PORT}                  # The port on the primary.

# Physical replicas.
NP_REPLICATION_PHYSICAL_SLOT=${NP_REPLICATION_PHYSICAL_SLOT}    # The physical slot that this replica will use.



# =====================================================================
# Default environment variable values.
# =====================================================================

if [ -z "$POSTGRES_USER" ]; then
  POSTGRES_USER="noisepage"
fi

if [ -z "$POSTGRES_DB" ]; then
  POSTGRES_DB="noisepage"
fi

if [ -z "$POSTGRES_HOST_AUTH_METHOD" ]; then
  POSTGRES_HOST_AUTH_METHOD="md5"
fi

if [ -z "$PGPORT" ]; then
  PGPORT=15721
fi

if [ -z "$NP_WAL_LEVEL" ]; then
  NP_WAL_LEVEL="replica"
fi

# =====================================================================
# Helper functions.
# =====================================================================

_pgctl_start() {
  ${BIN_DIR}/pg_ctl --pgdata=${PGDATA} -w start
}

_pg_stop() {
  if [ "${NP_REPLICATION_TYPE}" = "exploratory" ]; then
    ${BIN_DIR}/pg_ctl --pgdata=${PGDATA} -w --mode=immediate stop
  else
    ${BIN_DIR}/pg_ctl --pgdata=${PGDATA} -w stop
  fi
}

_pg_start() {
  if [ "${NP_REPLICATION_TYPE}" = "primary" ]; then
      (
        sleep 5
        IFS=','
        for publication in $(echo "${NP_REPLICATION_PUBLICATION_NAMES[@]}"); do
          echo $publication
          # Create logical replication publication(s).
          # Note that for updates/deletes to work, each table may need REPLICA IDENTITY to be manually set.
          ${BIN_DIR}/psql -c "create publication $publication for all tables" postgres
        done
      ) &
    fi

    ${BIN_DIR}/postgres "-D" "${PGDATA}" -p ${PGPORT}
}

_pg_initdb() {
  WALDIR="--waldir=${POSTGRES_INITDB_WALDIR}"
  if [ -z ${POSTGRES_INITDB_WALDIR} ]; then
    WALDIR=""
  fi
  ${BIN_DIR}/initdb --pgdata=${PGDATA} $WALDIR ${POSTGRES_INITDB_ARGS}
}

_pg_config() {
  AUTO_CONF=${PGDATA}/postgresql.auto.conf
  HBA_CONF=${PGDATA}/pg_hba.conf

  # pg_hba.conf
  echo "host all all 0.0.0.0/0 ${POSTGRES_HOST_AUTH_METHOD}" >> ${HBA_CONF}

  # postgresql.auto.conf
  # Allow Docker host to connect to container.
  echo "listen_addresses = '*'" >> ${AUTO_CONF}
}

_pg_create_user_and_db() {
  ${BIN_DIR}/psql -c "create user ${POSTGRES_USER} with login password '${POSTGRES_PASSWORD}'" postgres
  ${BIN_DIR}/psql -c "create database ${POSTGRES_DB} with owner = '${POSTGRES_USER}'" postgres
  # Enable monitoring for the created user.
  ${BIN_DIR}/psql -c "grant pg_monitor to ${POSTGRES_USER}" postgres
  # Make the created user a superuser.
  ${BIN_DIR}/psql -c "alter user ${POSTGRES_USER} with superuser" postgres
}

_pg_setup_replication() {
  AUTO_CONF=${PGDATA}/postgresql.auto.conf
  HBA_CONF=${PGDATA}/pg_hba.conf

  # See PostgreSQL docs for complete description of parameters.

  # wal_level: How much information to ship over.
  echo "wal_level = ${NP_WAL_LEVEL}" >> ${AUTO_CONF}
  # hot_standby: True to enable connecting and running queries during recovery.
  echo "hot_standby = on" >> ${AUTO_CONF}
  # max_wal_senders: Maximum number of concurrent connections to standby/backup clients.
  echo "max_wal_senders = 10" >> ${AUTO_CONF}
  # max_replication_slots: Maximum number of replication slots.
  echo "max_replication_slots = 10" >> ${AUTO_CONF}
  # hot_standby_feedback: True if standby should tell primary about what queries are currently executing.
  echo "hot_standby_feedback = on" >> ${AUTO_CONF}

  # PGTune configs (Most configs divided by two to accommodate two instances)
  # DB Version: 13
    # OS Type: linux
    # DB Type: oltp
    # Total Memory (RAM): 188 GB
    # CPUs num: 80
    # Number of connections: 50
    # Data Storage: SSD

  echo "max_connections = 100" >> ${AUTO_CONF}
  echo "shared_buffers = 23.5GB" >> ${AUTO_CONF}
  echo "effective_cache_size = 70.5GB" >> ${AUTO_CONF}
  echo "maintenance_work_mem = 2GB" >> ${AUTO_CONF}
  echo "checkpoint_completion_target = 0.9" >> ${AUTO_CONF}
  echo "wal_buffers = 16MB" >> ${AUTO_CONF}
  echo "default_statistics_target = 100" >> ${AUTO_CONF}
  echo "random_page_cost = 1.1" >> ${AUTO_CONF}
  echo "effective_io_concurrency = 200" >> ${AUTO_CONF}
  echo "work_mem = 123207.5kB" >> ${AUTO_CONF}
  echo "min_wal_size = 2GB" >> ${AUTO_CONF}
  echo "max_wal_size = 8GB" >> ${AUTO_CONF}
  echo "max_worker_processes = 80" >> ${AUTO_CONF}
  echo "max_parallel_workers_per_gather = 4" >> ${AUTO_CONF}
  echo "max_parallel_workers = 80" >> ${AUTO_CONF}
  echo "max_parallel_maintenance_workers = 4" >> ${AUTO_CONF}

  if [ "${NP_REPLICATION_TYPE}" = "primary" ]; then
    # ===============================
    # Enable replication.
    # ===============================

    # Create replication user.
    ${BIN_DIR}/psql -c "create user ${NP_REPLICATION_USER} with replication encrypted password '${NP_REPLICATION_PASSWORD}'" postgres
    # Allow replication user to connect..
    echo "host replication ${NP_REPLICATION_USER} 0.0.0.0/0 md5" >> ${HBA_CONF}
    # Reload configuration.
    ${BIN_DIR}/psql -c "select pg_reload_conf()" postgres
    echo ${NP_REPLICATION_PHYSICAL_SLOTS}
    (
      IFS=','
      for slot in $(echo "${NP_REPLICATION_PHYSICAL_SLOTS[@]}"); do
        echo $slot
        # Create replication slot(s) for replica.
        ${BIN_DIR}/psql -c "select pg_create_physical_replication_slot('$slot')" postgres
      done
    )
  fi
}

# All the steps required to start up PostgreSQL.
_pg_start_all() {
  if [ -e "${PGDATA}/base" ]; then
    _pgctl_start
  else
    _pg_initdb              # Initialize a new PostgreSQL cluster.
    _pg_config              # Write any configuration options required.
    _pgctl_start            # Start the PostgreSQL cluster.
    _pg_create_user_and_db  # Create the specified user and database.

    if [ ! -z "${NP_REPLICATION_TYPE}" ]; then
      _pg_setup_replication
    fi
  fi
}

# =====================================================================
# Main logic.
# =====================================================================

_wait_for_primary() {
  while true ; do
    # TODO(WAN): Issue #6 Note that there is a potential race here where the primary restarts and healthcheck succeeds.
    sleep 10
    ${BIN_DIR}/pg_isready --host=${NP_PRIMARY_NAME} --port=${NP_PRIMARY_PORT} --username=${NP_PRIMARY_USERNAME}
    READY_CHECK=$?
    if [ "$READY_CHECK" = "0" ]; then
      break
    fi
  done
}

_main_primary() {
  _pg_start_all
  _pg_stop
  _pg_start
}

_main_replica() {
  _wait_for_primary

  # Initialize replica backup from primary.
  rm -rf "${PGDATA:?}/"*
  echo ${NP_REPLICATION_PASSWORD} | ${BIN_DIR}/pg_basebackup --host ${NP_PRIMARY_NAME} --username ${NP_REPLICATION_USER} --port ${NP_PRIMARY_PORT} --pgdata=${PGDATA} --format=p --wal-method=stream --progress --write-recovery-conf --slot ${NP_REPLICATION_PHYSICAL_SLOT}
  _pg_start
}

_main_exploratory() {
  sudo chmod 700 "${PGDATA}"
  sudo chown -R terrier:terrier "${PGDATA}"
  rm -f "${PGDATA}/postmaster.pid"
  rm -f "${PGDATA}/standby.signal"
  "${BIN_DIR}"/pg_resetwal -f "${PGDATA}"
  _pg_start
}

_cleanup() {
  _pg_stop
}

main() {
  trap 'cleanup' SIGTERM
  if [ -z "${NP_REPLICATION_TYPE}" ] || [ "${NP_REPLICATION_TYPE}" = "primary" ]; then
    _main_primary
  elif [ "${NP_REPLICATION_TYPE}" = "replica" ]; then
    _main_replica
  elif [ "${NP_REPLICATION_TYPE}" = "exploratory" ]; then
    _main_exploratory
  else
    echo "Unknown replication type: ${NP_REPLICATION_TYPE}"
    exit 1
  fi
}

main
