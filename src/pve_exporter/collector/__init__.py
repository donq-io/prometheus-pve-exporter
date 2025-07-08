"""
Prometheus collecters for Proxmox VE cluster.
"""

import collections
import logging
from proxmoxer import ProxmoxAPI

from prometheus_client import CollectorRegistry, generate_latest

from pve_exporter.collector.cluster import (
    StatusCollector,
    ClusterResourcesCollector,
    ClusterNodeCollector,
    VersionCollector,
    ClusterInfoCollector,
)
from pve_exporter.collector.node import (
    NodeConfigCollector,
    NodeReplicationCollector,
    NodeAgentCollector,
)

logger = logging.getLogger(__name__)

CollectorsOptions = collections.namedtuple(
    "CollectorsOptions",
    [
        "status",
        "version",
        "node",
        "cluster",
        "resources",
        "config",
        "replication",
        "agent",
    ],
)


def collect_pve(config, host, cluster, node, options: CollectorsOptions):
    """Scrape a host and return prometheus text format for it"""

    logger.info(f"Starting PVE collection for host: {host}")
    logger.debug(f"Config: {config}")
    logger.debug(f"Cluster mode: {cluster}, Node mode: {node}")
    logger.debug(f"Collectors options: {options}")

    try:
        pve = ProxmoxAPI(host, **config)
        logger.info(f"Successfully created ProxmoxAPI connection to {host}")
    except Exception as e:
        logger.error(f"Failed to create ProxmoxAPI connection: {e}")
        raise

    registry = CollectorRegistry()
    if cluster and options.status:
        logger.debug("Registering StatusCollector")
        registry.register(StatusCollector(pve))
    if cluster and options.resources:
        logger.debug("Registering ClusterResourcesCollector")
        registry.register(ClusterResourcesCollector(pve))
    if cluster and options.node:
        logger.debug("Registering ClusterNodeCollector")
        registry.register(ClusterNodeCollector(pve))
    if cluster and options.cluster:
        logger.debug("Registering ClusterInfoCollector")
        registry.register(ClusterInfoCollector(pve))
    if cluster and options.version:
        logger.debug("Registering VersionCollector")
        registry.register(VersionCollector(pve))
    if node and options.config:
        logger.debug("Registering NodeConfigCollector")
        registry.register(NodeConfigCollector(pve))
    if node and options.replication:
        logger.debug("Registering NodeReplicationCollector")
        registry.register(NodeReplicationCollector(pve))
    if node and options.agent:
        logger.debug("Registering NodeAgentCollector")
        registry.register(NodeAgentCollector(pve))

    logger.info("Starting metrics collection")
    return generate_latest(registry)
