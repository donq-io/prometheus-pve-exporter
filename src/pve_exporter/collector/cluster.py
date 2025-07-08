"""
Prometheus collecters for Proxmox VE cluster.
"""

# pylint: disable=too-few-public-methods

import itertools
import logging

from prometheus_client.core import GaugeMetricFamily

logger = logging.getLogger(__name__)


class StatusCollector:
    """
    Collects Proxmox VE Node/VM/CT-Status

    # HELP pve_up Node/VM/CT-Status is online/running
    # TYPE pve_up gauge
    pve_up{id="node/proxmox-host"} 1.0
    pve_up{id="cluster/pvec"} 1.0
    pve_up{id="lxc/101"} 1.0
    pve_up{id="qemu/102"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        status_metrics = GaugeMetricFamily(
            "pve_up", "Node/VM/CT-Status is online/running", labels=["id"]
        )

        logger.info("StatusCollector: Fetching cluster status...")
        try:
            cluster_status = self._pve.cluster.status.get()
            logger.debug(
                f"StatusCollector: Received cluster status response: {cluster_status}"
            )
            logger.debug(f"StatusCollector: Response type: {type(cluster_status)}")

            if not isinstance(cluster_status, list):
                logger.error(
                    f"StatusCollector: Expected list but got {type(cluster_status)}"
                )
                logger.error(f"StatusCollector: Content: {cluster_status}")
                return

            for i, entry in enumerate(cluster_status):
                logger.debug(f"StatusCollector: Processing entry {i}: {entry}")
                logger.debug(f"StatusCollector: Entry type: {type(entry)}")

                if not isinstance(entry, dict):
                    logger.error(
                        f"StatusCollector: Entry {i} is not a dict but {type(entry)}: {entry}"
                    )
                    continue

                if "type" not in entry:
                    logger.error(
                        f"StatusCollector: Entry {i} missing 'type' key. Keys: {entry.keys()}"
                    )
                    continue

                if entry["type"] == "node":
                    label_values = [entry["id"]]
                    status_metrics.add_metric(label_values, entry["online"])
                elif entry["type"] == "cluster":
                    label_values = [f"cluster/{entry['name']}"]
                    status_metrics.add_metric(label_values, entry["quorate"])
                else:
                    raise ValueError(
                        f"Got unexpected status entry type {entry['type']}"
                    )
        except Exception as e:
            logger.exception(f"StatusCollector: Error while collecting status: {e}")
            raise

        logger.info("StatusCollector: Fetching cluster resources...")
        try:
            vm_resources = self._pve.cluster.resources.get(type="vm")
            logger.debug(f"StatusCollector: Received VM resources: {vm_resources}")

            for resource in vm_resources:
                label_values = [resource["id"]]
                status_metrics.add_metric(label_values, resource["status"] == "running")
        except Exception as e:
            logger.exception(
                f"StatusCollector: Error while collecting VM resources: {e}"
            )

        logger.info("StatusCollector: Fetching storage resources...")
        try:
            storage_resources = self._pve.cluster.resources.get(type="storage")
            logger.debug(
                f"StatusCollector: Received storage resources: {storage_resources}"
            )

            for resource in storage_resources:
                label_values = [resource["id"]]
                status_metrics.add_metric(
                    label_values, resource["status"] == "available"
                )
        except Exception as e:
            logger.exception(
                f"StatusCollector: Error while collecting storage resources: {e}"
            )

        yield status_metrics


class VersionCollector:
    """
    Collects Proxmox VE build information. E.g.:

    # HELP pve_version_info Proxmox VE version info
    # TYPE pve_version_info gauge
    pve_version_info{release="15",repoid="7599e35a",version="4.4"} 1.0
    """

    LABEL_WHITELIST = ["release", "repoid", "version"]

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        logger.info("VersionCollector: Fetching version info...")
        try:
            version_data = self._pve.version.get()
            logger.debug(f"VersionCollector: Received version data: {version_data}")

            version_items = version_data.items()
            version = {
                key: value
                for key, value in version_items
                if key in self.LABEL_WHITELIST
            }

            labels, label_values = zip(*version.items())
            metric = GaugeMetricFamily(
                "pve_version_info", "Proxmox VE version info", labels=labels
            )
            metric.add_metric(label_values, 1)

            yield metric
        except Exception as e:
            logger.exception(f"VersionCollector: Error while collecting version: {e}")


class ClusterNodeCollector:
    """
    Collects Proxmox VE cluster node information. E.g.:

    # HELP pve_node_info Node info
    # TYPE pve_node_info gauge
    pve_node_info{id="node/proxmox-host", level="c", name="proxmox-host",
        nodeid="0"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        logger.info("ClusterNodeCollector: Fetching cluster nodes...")
        try:
            cluster_status = self._pve.cluster.status.get()
            logger.debug(
                f"ClusterNodeCollector: Received cluster status: {cluster_status}"
            )

            nodes = [
                entry
                for entry in cluster_status
                if isinstance(entry, dict) and entry.get("type") == "node"
            ]
            logger.debug(f"ClusterNodeCollector: Found {len(nodes)} nodes")

            labels = ["id", "level", "name", "nodeid"]

            if nodes:
                info_metrics = GaugeMetricFamily(
                    "pve_node_info", "Node info", labels=labels
                )

                for node in nodes:
                    label_values = [str(node[key]) for key in labels]
                    info_metrics.add_metric(label_values, 1)

                yield info_metrics
        except Exception as e:
            logger.exception(f"ClusterNodeCollector: Error while collecting nodes: {e}")


class ClusterInfoCollector:
    """
    Collects Proxmox VE cluster information. E.g.:

    # HELP pve_cluster_info Cluster info
    # TYPE pve_cluster_info gauge
    pve_cluster_info{id="cluster/pvec",nodes="2",quorate="1",version="2"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        logger.info("ClusterInfoCollector: Fetching cluster info...")
        try:
            cluster_status = self._pve.cluster.status.get()
            logger.debug(
                f"ClusterInfoCollector: Received cluster status: {cluster_status}"
            )

            clusters = [
                entry
                for entry in cluster_status
                if isinstance(entry, dict) and entry.get("type") == "cluster"
            ]
            logger.debug(f"ClusterInfoCollector: Found {len(clusters)} clusters")

            if clusters:
                # Remove superflous keys.
                for cluster in clusters:
                    del cluster["type"]

                # Add cluster-prefix to id.
                for cluster in clusters:
                    cluster["id"] = f"cluster/{cluster['name']}"
                    del cluster["name"]

                # Yield remaining data.
                labels = clusters[0].keys()
                info_metrics = GaugeMetricFamily(
                    "pve_cluster_info", "Cluster info", labels=labels
                )

                for cluster in clusters:
                    label_values = [str(cluster[key]) for key in labels]
                    info_metrics.add_metric(label_values, 1)

                yield info_metrics
        except Exception as e:
            logger.exception(
                f"ClusterInfoCollector: Error while collecting cluster info: {e}"
            )


class HighAvailabilityStateMetric(GaugeMetricFamily):
    """
    A single gauge representing PVE ha state.
    """

    GUEST_STATES = [
        "stopped",
        "request_stop",
        "request_start",
        "request_start_balance",
        "started",
        "fence",
        "recovery",
        "migrate",
        "relocate",
        "freeze",
        "error",
    ]

    NODE_STATES = ["online", "maintenance", "unknown", "fence", "gone"]

    STATES = {
        "lxc": GUEST_STATES,
        "qemu": GUEST_STATES,
        "node": NODE_STATES,
    }

    def __init__(self):
        super().__init__(
            "pve_ha_state",
            "HA service status (for HA managed VMs).",
            labels=["id", "state"],
        )

    def add_metric_from_resource(self, resource: dict):
        """Inspect resource and add suitable metric- to the metric family.

        Args:
          resource: A PVE cluster resource
        """
        restype = resource["type"]
        if restype in self.STATES:
            for state in self.STATES[restype]:
                value = resource.get("hastate", None) == state
                self.add_metric([resource["id"], state], value)


class LockStateMetric(GaugeMetricFamily):
    """
    A single gauge representing PVE guest lock state.
    """

    GUEST_STATES = [
        "backup",
        "clone",
        "create",
        "migrate",
        "rollback",
        "snapshot",
        "snapshot-delete",
        "suspended",
        "suspending",
    ]

    STATES = {
        "qemu": GUEST_STATES,
        "lxc": GUEST_STATES,
    }

    def __init__(self):
        super().__init__(
            "pve_lock_state",
            "The guest's current config lock (for types 'qemu' and 'lxc')",
            labels=["id", "state"],
        )

    def add_metric_from_resource(self, resource: dict):
        """Inspect resource and add suitable metric- to the metric family.

        Args:
          resource: A PVE cluster resource
        """
        restype = resource["type"]
        if restype in self.STATES:
            for state in self.STATES[restype]:
                value = resource.get("lock", None) == state
                self.add_metric([resource["id"], state], value)


class ClusterResourcesCollector:
    """
    Collects Proxmox VE cluster resources information, i.e. memory, storage, cpu
    usage for cluster nodes and guests.
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        logger.info("ClusterResourcesCollector: Starting collection...")

        metrics = {
            "maxdisk": GaugeMetricFamily(
                "pve_disk_size_bytes",
                (
                    "Storage size in bytes (for type 'storage'), root image size for VMs "
                    "(for types 'qemu' and 'lxc')."
                ),
                labels=["id"],
            ),
            "disk": GaugeMetricFamily(
                "pve_disk_usage_bytes",
                (
                    "Used disk space in bytes (for type 'storage'), used root image space for VMs "
                    "(for types 'qemu' and 'lxc')."
                ),
                labels=["id"],
            ),
            "maxmem": GaugeMetricFamily(
                "pve_memory_size_bytes",
                "Number of available memory in bytes (for types 'node', 'qemu' and 'lxc').",
                labels=["id"],
            ),
            "mem": GaugeMetricFamily(
                "pve_memory_usage_bytes",
                "Used memory in bytes (for types 'node', 'qemu' and 'lxc').",
                labels=["id"],
            ),
            "netout": GaugeMetricFamily(
                "pve_network_transmit_bytes",
                (
                    "The amount of traffic in bytes that was sent from the guest over the network "
                    "since it was started. (for types 'qemu' and 'lxc')"
                ),
                labels=["id"],
            ),
            "netin": GaugeMetricFamily(
                "pve_network_receive_bytes",
                (
                    "The amount of traffic in bytes that was sent to the guest over the network "
                    "since it was started. (for types 'qemu' and 'lxc')"
                ),
                labels=["id"],
            ),
            "diskwrite": GaugeMetricFamily(
                "pve_disk_write_bytes",
                (
                    "The amount of bytes the guest wrote to its block devices since the guest was "
                    "started. This info is not available for all storage types. "
                    "(for types 'qemu' and 'lxc')"
                ),
                labels=["id"],
            ),
            "diskread": GaugeMetricFamily(
                "pve_disk_read_bytes",
                (
                    "The amount of bytes the guest read from its block devices since the guest was "
                    "started. This info is not available for all storage types. "
                    "(for types 'qemu' and 'lxc')"
                ),
                labels=["id"],
            ),
            "cpu": GaugeMetricFamily(
                "pve_cpu_usage_ratio",
                "CPU utilization (for types 'node', 'qemu' and 'lxc').",
                labels=["id"],
            ),
            "maxcpu": GaugeMetricFamily(
                "pve_cpu_usage_limit",
                "Number of available CPUs (for types 'node', 'qemu' and 'lxc').",
                labels=["id"],
            ),
            "uptime": GaugeMetricFamily(
                "pve_uptime_seconds",
                "Uptime of node or virtual guest in seconds (for types 'node', 'qemu' and 'lxc').",
                labels=["id"],
            ),
            "shared": GaugeMetricFamily(
                "pve_storage_shared",
                "Whether or not the storage is shared among cluster nodes",
                labels=["id"],
            ),
        }

        ha_metric = HighAvailabilityStateMetric()
        lock_metric = LockStateMetric()

        info_metrics = {
            "guest": GaugeMetricFamily(
                "pve_guest_info",
                "VM/CT info",
                labels=["id", "node", "name", "type", "template", "tags"],
            ),
            "storage": GaugeMetricFamily(
                "pve_storage_info",
                "Storage info",
                labels=["id", "node", "storage", "plugintype", "content"],
            ),
        }

        info_lookup = {
            "lxc": {
                "labels": ["id", "node", "name", "type", "template", "tags"],
                "gauge": info_metrics["guest"],
            },
            "qemu": {
                "labels": ["id", "node", "name", "type", "template", "tags"],
                "gauge": info_metrics["guest"],
            },
            "storage": {
                "labels": ["id", "node", "storage", "plugintype", "content"],
                "gauge": info_metrics["storage"],
            },
        }

        try:
            resources = self._pve.cluster.resources.get()
            logger.debug(
                f"ClusterResourcesCollector: Received {len(resources)} resources"
            )

            for i, resource in enumerate(resources):
                logger.debug(
                    f"ClusterResourcesCollector: Processing resource {i}: {resource}"
                )

                restype = resource["type"]

                if restype in info_lookup:
                    labels = info_lookup[restype]["labels"]
                    label_values = [str(resource.get(key, "")) for key in labels]
                    info_lookup[restype]["gauge"].add_metric(label_values, 1)

                ha_metric.add_metric_from_resource(resource)
                lock_metric.add_metric_from_resource(resource)

                label_values = [resource["id"]]
                for key, metric_value in resource.items():
                    if key in metrics:
                        metrics[key].add_metric(label_values, metric_value)

        except Exception as e:
            logger.exception(
                f"ClusterResourcesCollector: Error while collecting resources: {e}"
            )

        return itertools.chain(
            metrics.values(), [ha_metric, lock_metric], info_metrics.values()
        )
