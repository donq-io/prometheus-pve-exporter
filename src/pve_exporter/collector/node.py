"""
Prometheus collecters for Proxmox VE cluster.
"""

# pylint: disable=too-few-public-methods

import logging
import itertools

from prometheus_client.core import GaugeMetricFamily

logger = logging.getLogger(__name__)


class NodeConfigCollector:
    """
    Collects Proxmox VE VM information directly from config, i.e. boot, name, onboot, etc.
    For manual test: "pvesh get /nodes/<node>/<type>/<vmid>/config"

    # HELP pve_onboot_status Proxmox vm config onboot value
    # TYPE pve_onboot_status gauge
    pve_onboot_status{id="qemu/113",node="XXXX",type="qemu"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve
        self._log = logging.getLogger(__name__)

    def collect(self):  # pylint: disable=missing-docstring
        self._log.info("NodeConfigCollector: Starting collection")

        metrics = {
            "onboot": GaugeMetricFamily(
                "pve_onboot_status",
                "Proxmox vm config onboot value",
                labels=["id", "node", "type"],
            ),
        }

        node = None
        try:
            cluster_status = self._pve.cluster.status.get()
            self._log.debug(
                f"NodeConfigCollector: Received cluster status: {cluster_status}"
            )

            for entry in cluster_status:
                if (
                    isinstance(entry, dict)
                    and entry.get("type") == "node"
                    and entry.get("local")
                ):
                    node = entry["name"]
                    self._log.info(f"NodeConfigCollector: Found local node: {node}")
                    break
        except Exception as e:
            self._log.exception(
                f"NodeConfigCollector: Error getting cluster status: {e}"
            )
            return []

        if node is None:
            self._log.error("NodeConfigCollector: Unable to determine local node name")
            return []

        # Scrape qemu config
        vmtype = "qemu"
        try:
            qemu_vms = self._pve.nodes(node).qemu.get()
            self._log.debug(
                f"NodeConfigCollector: Found {len(qemu_vms)} QEMU VMs on node {node}"
            )

            for vmdata in qemu_vms:
                try:
                    config = (
                        self._pve.nodes(node).qemu(vmdata["vmid"]).config.get().items()
                    )
                    self._log.debug(
                        f"NodeConfigCollector: VM {vmdata['vmid']} config: {dict(config)}"
                    )

                    for key, metric_value in config:
                        label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype]
                        if key in metrics:
                            metrics[key].add_metric(label_values, metric_value)
                except Exception as e:
                    self._log.warning(
                        f"NodeConfigCollector: Error getting config for QEMU VM {vmdata['vmid']}: {e}"
                    )
        except Exception as e:
            self._log.exception(f"NodeConfigCollector: Error getting QEMU VMs: {e}")

        # Scrape LXC config
        vmtype = "lxc"
        try:
            lxc_vms = self._pve.nodes(node).lxc.get()
            self._log.debug(
                f"NodeConfigCollector: Found {len(lxc_vms)} LXC containers on node {node}"
            )

            for vmdata in lxc_vms:
                try:
                    config = (
                        self._pve.nodes(node).lxc(vmdata["vmid"]).config.get().items()
                    )
                    self._log.debug(
                        f"NodeConfigCollector: LXC {vmdata['vmid']} config: {dict(config)}"
                    )

                    for key, metric_value in config:
                        label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype]
                        if key in metrics:
                            metrics[key].add_metric(label_values, metric_value)
                except Exception as e:
                    self._log.warning(
                        f"NodeConfigCollector: Error getting config for LXC {vmdata['vmid']}: {e}"
                    )
        except Exception as e:
            self._log.exception(
                f"NodeConfigCollector: Error getting LXC containers: {e}"
            )

        return metrics.values()


class NodeReplicationCollector:
    """
    Collects Proxmox VE Replication information directly from status, i.e. replication duration,
    last_sync, last_try, next_sync, fail_count.
    For manual test: "pvesh get /nodes/<node>/replication/<id>/status"
    """

    def __init__(self, pve):
        self._pve = pve
        self._log = logging.getLogger(__name__)

    def collect(self):  # pylint: disable=missing-docstring
        self._log.info("NodeReplicationCollector: Starting collection")

        info_metrics = {
            "info": GaugeMetricFamily(
                "pve_replication_info",
                "Proxmox vm replication info",
                labels=["id", "type", "source", "target", "guest"],
            )
        }

        metrics = {
            "duration": GaugeMetricFamily(
                "pve_replication_duration_seconds",
                "Proxmox vm replication duration",
                labels=["id"],
            ),
            "last_sync": GaugeMetricFamily(
                "pve_replication_last_sync_timestamp_seconds",
                "Proxmox vm replication last_sync",
                labels=["id"],
            ),
            "last_try": GaugeMetricFamily(
                "pve_replication_last_try_timestamp_seconds",
                "Proxmox vm replication last_try",
                labels=["id"],
            ),
            "next_sync": GaugeMetricFamily(
                "pve_replication_next_sync_timestamp_seconds",
                "Proxmox vm replication next_sync",
                labels=["id"],
            ),
            "fail_count": GaugeMetricFamily(
                "pve_replication_failed_syncs",
                "Proxmox vm replication fail_count",
                labels=["id"],
            ),
        }

        node = None
        try:
            cluster_status = self._pve.cluster.status.get()
            self._log.debug(
                f"NodeReplicationCollector: Received cluster status: {cluster_status}"
            )

            for entry in cluster_status:
                if (
                    isinstance(entry, dict)
                    and entry.get("type") == "node"
                    and entry.get("local")
                ):
                    node = entry["name"]
                    self._log.info(
                        f"NodeReplicationCollector: Found local node: {node}"
                    )
                    break
        except Exception as e:
            self._log.exception(
                f"NodeReplicationCollector: Error getting cluster status: {e}"
            )
            return []

        if node is None:
            self._log.error(
                "NodeReplicationCollector: Unable to determine local node name"
            )
            return []

        try:
            replication_jobs = self._pve.nodes(node).replication.get()
            self._log.debug(
                f"NodeReplicationCollector: Found {len(replication_jobs)} replication jobs"
            )

            for jobdata in replication_jobs:
                self._log.debug(
                    f"NodeReplicationCollector: Processing job {jobdata['id']}: {jobdata}"
                )

                # Add info metric
                label_values = [
                    str(jobdata["id"]),
                    str(jobdata["type"]),
                    f"node/{jobdata['source']}",
                    f"node/{jobdata['target']}",
                    f"{jobdata['vmtype']}/{jobdata['guest']}",
                ]
                info_metrics["info"].add_metric(label_values, 1)

                # Add metrics
                try:
                    label_values = [str(jobdata["id"])]
                    status = (
                        self._pve.nodes(node).replication(jobdata["id"]).status.get()
                    )
                    self._log.debug(
                        f"NodeReplicationCollector: Job {jobdata['id']} status: {status}"
                    )

                    for key, metric_value in status.items():
                        if key in metrics:
                            metrics[key].add_metric(label_values, metric_value)
                except Exception as e:
                    self._log.warning(
                        f"NodeReplicationCollector: Error getting status for job {jobdata['id']}: {e}"
                    )
        except Exception as e:
            self._log.exception(
                f"NodeReplicationCollector: Error getting replication jobs: {e}"
            )

        return itertools.chain(metrics.values(), info_metrics.values())


class NodeAgentCollector:
    """
    Collects Proxmox VE QEMU Agent information for VMs.
    For manual test: "pvesh get /nodes/<node>/qemu/<vmid>/agent"
    """

    def __init__(self, pve):
        self._pve = pve
        self._log = logging.getLogger(__name__)

    def collect(self):  # pylint: disable=missing-docstring
        self._log.info("NodeAgentCollector: Starting collection")

        metrics = {
            "agent_enabled": GaugeMetricFamily(
                "pve_qemu_agent_enabled",
                "Proxmox VM QEMU agent is enabled in config (1) or disabled (0)",
                labels=["id", "node"],
            ),
            "agent_status": GaugeMetricFamily(
                "pve_qemu_agent_status",
                "Proxmox VM QEMU agent status (1 if running)",
                labels=["id", "node"],
            ),
            "fs_total_bytes": GaugeMetricFamily(
                "pve_qemu_agent_fs_total_bytes",
                "Total bytes available in filesystem",
                labels=["id", "node", "mountpoint", "fstype", "device"],
            ),
            "fs_used_bytes": GaugeMetricFamily(
                "pve_qemu_agent_fs_used_bytes",
                "Used bytes in filesystem",
                labels=["id", "node", "mountpoint", "fstype", "device"],
            ),
            "fs_usage_ratio": GaugeMetricFamily(
                "pve_qemu_agent_fs_usage_ratio",
                "Ratio of used space on filesystem (0-1)",
                labels=["id", "node", "mountpoint", "fstype", "device"],
            ),
        }

        node = None
        try:
            cluster_status = self._pve.cluster.status.get()
            self._log.debug(
                f"NodeAgentCollector: Received cluster status: {cluster_status}"
            )

            for entry in cluster_status:
                if (
                    isinstance(entry, dict)
                    and entry.get("type") == "node"
                    and entry.get("local")
                ):
                    node = entry["name"]
                    self._log.info(f"NodeAgentCollector: Found local node: {node}")
                    break
        except Exception as e:
            self._log.exception(
                f"NodeAgentCollector: Error getting cluster status: {e}"
            )
            return []

        if node is None:
            self._log.warning("Unable to determine local node name")
            return []

        # Raccoglie dati solo per macchine virtuali QEMU
        try:
            qemu_vms = self._pve.nodes(node).qemu.get()
            self._log.debug(f"NodeAgentCollector: Found {len(qemu_vms)} QEMU VMs")

            for vmdata in qemu_vms:
                vm_id = vmdata["vmid"]
                label_values = [f"qemu/{vm_id}", node]

                # Verifica nella configurazione se l'agente è abilitato
                try:
                    config = self._pve.nodes(node).qemu(vm_id).config.get()
                    self._log.debug(f"NodeAgentCollector: VM {vm_id} config: {config}")

                    agent_enabled = 1 if config.get("agent", "0") == "1" else 0
                    metrics["agent_enabled"].add_metric(label_values, agent_enabled)

                    # Controlla lo stato dell'agente solo se è abilitato
                    if agent_enabled:
                        try:
                            # Verifica se l'agente QEMU è in esecuzione utilizzando get-host-name invece di ping
                            agent_hostname = (
                                self._pve.nodes(node)
                                .qemu(vm_id)
                                .agent("get-host-name")
                                .get()
                            )
                            self._log.debug(
                                f"NodeAgentCollector: VM {vm_id} agent response: {agent_hostname}"
                            )

                            # Se otteniamo una risposta con result.host-name, l'agente è attivo
                            agent_running = 0
                            if "result" in agent_hostname:
                                if "host-name" in agent_hostname["result"]:
                                    agent_running = 1
                                    self._log.debug(
                                        f"Agent running for VM {vm_id}, hostname: {agent_hostname['result']['host-name']}"
                                    )

                            metrics["agent_status"].add_metric(
                                label_values, agent_running
                            )

                            if agent_running:
                                # Ottiene informazioni sull'agente QEMU
                                try:
                                    fs_info = (
                                        self._pve.nodes(node)
                                        .qemu(vm_id)
                                        .agent("get-fsinfo")
                                        .get()
                                    )

                                    # Aggiunge un log dettagliato per il debug
                                    self._log.debug(
                                        f"Filesystem info for VM {vm_id}: {fs_info}"
                                    )

                                    # Verifica nella risposta della chiamata
                                    if "result" in fs_info:
                                        # Log per verificare la struttura del risultato
                                        self._log.debug(
                                            f"Result structure for VM {vm_id}: {fs_info['result']}"
                                        )

                                        if not fs_info["result"]:
                                            self._log.warning(
                                                f"Empty filesystem info result for VM {vm_id}"
                                            )

                                        for fs in fs_info["result"]:
                                            # Log per verificare ogni elemento del filesystem
                                            self._log.debug(
                                                f"Processing filesystem entry for VM {vm_id}: {fs}"
                                            )

                                            # Verifica che i campi necessari esistano
                                            if (
                                                "total-bytes" not in fs
                                                or "used-bytes" not in fs
                                            ):
                                                self._log.warning(
                                                    f"Missing required fields in filesystem info for VM {vm_id}: {fs}"
                                                )
                                                continue

                                            # Estrae i valori necessari
                                            total_bytes = fs.get("total-bytes", 0)
                                            used_bytes = fs.get("used-bytes", 0)
                                            mountpoint = fs.get("mountpoint", "unknown")
                                            fstype = fs.get("type", "unknown")

                                            # Ottiene il nome del dispositivo
                                            device = fs.get("name", "unknown")
                                            # Se ci sono informazioni sui dischi, usa il first dev path
                                            if (
                                                "disk" in fs
                                                and fs["disk"]
                                                and "dev" in fs["disk"][0]
                                            ):
                                                device = fs["disk"][0]["dev"]

                                            # Prepara le etichette
                                            fs_labels = [
                                                f"qemu/{vm_id}",
                                                node,
                                                mountpoint,
                                                fstype,
                                                device,
                                            ]

                                            # Aggiunge le metriche
                                            metrics["fs_total_bytes"].add_metric(
                                                fs_labels, total_bytes
                                            )
                                            metrics["fs_used_bytes"].add_metric(
                                                fs_labels, used_bytes
                                            )

                                            # Calcola e aggiunge il rapporto di utilizzo
                                            usage_ratio = 0
                                            if total_bytes > 0:
                                                usage_ratio = used_bytes / total_bytes
                                            metrics["fs_usage_ratio"].add_metric(
                                                fs_labels, usage_ratio
                                            )
                                except Exception as e:  # pylint: disable=broad-except
                                    self._log.warning(
                                        f"Error fetching filesystem info for VM {vm_id}: {str(e)}"
                                    )
                        except Exception as e:  # pylint: disable=broad-except
                            # L'agente è abilitato ma non risponde
                            self._log.debug(
                                f"Agent enabled but not running for VM {vm_id}: {str(e)}"
                            )
                            metrics["agent_status"].add_metric(label_values, 0)
                    else:
                        # Se l'agente non è abilitato, imposta lo stato a 0
                        metrics["agent_status"].add_metric(label_values, 0)
                except Exception as e:  # pylint: disable=broad-except
                    self._log.warning(f"Error fetching config for VM {vm_id}: {str(e)}")
        except Exception as e:
            self._log.exception(f"NodeAgentCollector: Error getting QEMU VMs: {e}")

        return metrics.values()
