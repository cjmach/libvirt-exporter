/*
 * Copyright (C) 2022  Carlos Machado
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/prometheus/client_golang/prometheus"
	"libvirt.org/go/libvirt"
)

const (
	namespace = "virt"
	subsystem = "domain"
)

var (
	// 1. Domain Metrics
	// 1.1 General info
	infoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "info"),
		"General domain information.",
		[]string{"domain_id", "domain_name", "domain_state", "connection_uri"}, nil)
	cpuCountDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "cpu_count"),
		"The number of virtual CPUs for the domain.",
		[]string{"connection_uri", "domain_name"}, nil)
	maxMemoryBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "max_memory_bytes"),
		"The maximum memory in bytes allowed.",
		[]string{"connection_uri", "domain_name"}, nil)
	usedMemoryBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "used_memory_bytes"),
		"The memory in bytes used by the domain.",
		[]string{"connection_uri", "domain_name"}, nil)

	// 1.2 CPU stats
	cpuSecondsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "cpu_seconds_total"),
		"Total user and system CPU time spent in seconds.",
		[]string{"connection_uri", "domain_name"}, nil)
	cpuSystemSecondsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "cpu_system_seconds_total"),
		"System CPU time spent in seconds.",
		[]string{"connection_uri", "domain_name"}, nil)
	cpuUserSecondsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "cpu_user_seconds_total"),
		"User CPU time spent in seconds.",
		[]string{"connection_uri", "domain_name"}, nil)

	// 1.3 Memory stats
	memstatsSwapInBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_swap_in_bytes"),
		"The total amount of data read from swap space (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsSwapOutBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_swap_out_bytes"),
		"The total amount of memory written out to swap space (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsMajorFaultsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_major_faults_total"),
		"The number of page faults that required disk I/O to service.",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsMinorFaultsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_minor_faults_total"),
		"The number of page faults serviced without disk I/O.",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsUnusedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_unused_bytes"),
		"The amount of memory which is not being used for any purpose (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsAvailableBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_available_bytes"),
		"The total amount of memory available to the domain's OS (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsUsableBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_usable_bytes"),
		"How much the balloon can be inflated without pushing the guest system to swap, corresponds to 'Available' in /proc/meminfo.",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsActualBalloonBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_actual_balloon_bytes"),
		"Current balloon value (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsRssBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_rss_bytes"),
		"Resident Set Size of the process running the domain (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsLastUpdateSecondsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_last_update_seconds"),
		"Timestamp of the last statistic.",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsDiskCachesBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_disk_caches_bytes"),
		"Memory that can be reclaimed without additional I/O, typically disk caches (in bytes).",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsHugetblPgallocTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_hugetbl_pgalloc_total"),
		"The number of successful huge page allocations from inside the domain.",
		[]string{"connection_uri", "domain_name"}, nil)
	memstatsHugetblPgfailTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "memstats_hugetbl_pgfail_total"),
		"The number of failed huge page allocations from inside the domain.",
		[]string{"connection_uri", "domain_name"}, nil)

	// 1.4 Block info
	blockCapacityBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_capacity_bytes"),
		"Logical size in bytes of the image (how much storage the guest will see).",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	blockAllocationBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_allocation_bytes"),
		"Host storage in bytes occupied by the image (such as highest allocated extent if there are no holes, similar to 'du').",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	blockPhysicalBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_physical_bytes"),
		"Host physical size in bytes of the image container (last offset, similar to 'ls').",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	// 1.5 Block stats
	blockReadRequestsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_read_requests_total"),
		"Number of read requests.",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	blockReadBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_read_bytes"),
		"Number of read bytes.",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	blockWriteRequestsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_write_requests_total"),
		"Number of write requests.",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	blockWriteBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_write_bytes"),
		"Number of written bytes.",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)
	blockErrorsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "block_errors_total"),
		"In Xen this returns the mysterious 'oo_req'.",
		[]string{"connection_uri", "domain_name", "disk_name"}, nil)

	// 1.6 Disk errors
	diskErrorInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "disk_error_info"),
		"Information about disks that encountered an I/O error.",
		[]string{"connection_uri", "domain_name", "disk_name", "error"}, nil)

	// 1.7 FS info
	fsInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "fs_info"),
		"Information for each mounted file systems within the specified guest and the disks.",
		[]string{"connection_uri", "domain_name", "mountpoint", "device_name", "fstype"}, nil)

	// 1.8 Interface stats
	ifstatsRxBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_rx_bytes"),
		"Amount of data received (in bytes).",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsRxPacketsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_rx_packets_total"),
		"The number of received packets.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsRxErrorsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_rx_errors_total"),
		"The number of errors occurred on receive.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsRxDropTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_rx_drop_total"),
		"The number of packets dropped on receive.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsTxBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_tx_bytes"),
		"Amount of data sent (in bytes).",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsTxPacketsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_tx_packets_total"),
		"The number of sent packets.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsTxErrorsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_tx_errors_total"),
		"The number of errors occurred on send.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	ifstatsTxDropTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "ifstats_tx_drop_total"),
		"The number of packets dropped on send.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)

	// 1.9 Guest info
	// 1.9.1 Users
	guestActiveUsersTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_active_users_total"),
		"The number of currently active users on this domain.",
		[]string{"connection_uri", "domain_name"}, nil)
	// 1.9.2 OS
	guestOsInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_os_info"),
		"Information about the operating system running within the guest.",
		[]string{"connection_uri", "domain_name", "os_name", "os_version", "kernel_release", "kernel_version", "machine", "os_variant"}, nil)
	// 1.9.3 Timezone
	guestTimezoneOffsetDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_timezone_offset"),
		"Information about the timezone within the domain.",
		[]string{"connection_uri", "domain_name", "tz_name"}, nil)
	// 1.9.4 File System
	guestFsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_fs_total"),
		"The number of filesystems defined on this domain.",
		[]string{"connection_uri", "domain_name"}, nil)
	guestFsInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_fs_info"),
		"Information about the filesystems within the domain.",
		[]string{"connection_uri", "domain_name", "fs_name", "mountpoint", "fstype"}, nil)
	guestFsSizeBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_fs_size_bytes"),
		"The total size of the filesystem (in bytes).",
		[]string{"connection_uri", "domain_name", "fs_name"}, nil)
	guestFsUsedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_fs_used_bytes"),
		"The number of bytes used in the filesystem.",
		[]string{"connection_uri", "domain_name", "fs_name"}, nil)
	guestFsDisksTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_fs_disks_total"),
		"The number of disks targeted by this filesystem.",
		[]string{"connection_uri", "domain_name", "fs_name"}, nil)
	guestFsDiskInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_fs_disk_info"),
		"Information about a disk target by this filesystem.",
		[]string{"connection_uri", "domain_name", "fs_name", "device_alias", "serial_number", "device_node"}, nil)
	// 1.9.5 Disks
	guestDisksTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_disks_total"),
		"The number of disks defined on this domain.",
		[]string{"connection_uri", "domain_name"}, nil)
	guestDiskInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_disk_info"),
		"Information about the disks within the domain.",
		[]string{"connection_uri", "domain_name", "device_name", "partition", "device_alias", "guest_alias"}, nil)
	guestDiskDependencyCountDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_disk_dependencies_total"),
		"The number of device dependencies.",
		[]string{"connection_uri", "domain_name", "device_name"}, nil)
	guestHostnameInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_hostname"),
		"The hostname of the domain,",
		[]string{"connection_uri", "domain_name", "hostname"}, nil)
	// 1.9.6 Interfaces
	guestIfacesTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_ifaces_total"),
		"The number of interfaces defined on this domain.",
		[]string{"connection_uri", "domain_name"}, nil)
	guestIfaceInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_iface_info"),
		"Information about the interfaces within the domain.",
		[]string{"connection_uri", "domain_name", "iface_name", "hwaddr"}, nil)
	guestIfaceAddrTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_iface_addr_total"),
		"The number of IP addresses of this interface.",
		[]string{"connection_uri", "domain_name", "iface_name"}, nil)
	guestIfaceAddrInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "guest_iface_addr_info"),
		"Information about an IP address.",
		[]string{"connection_uri", "domain_name", "iface_name", "addr_type", "addr_ip", "addr_prefix"}, nil)

	// 2. Connect
	// 2.1 General info
	connectInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "connect", "info"),
		"Information about connection to the hypervisor.",
		[]string{"connection_uri", "hostname", "lib_version", "type", "encrypted", "secure"}, nil)

	// 3. Node
	// 3.1 CPU stats
	nodeCpuKernelTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "kernel_time_seconds"),
		"The cumulative CPU time which spends by kernel, when the node booting up.",
		[]string{"connection_uri"}, nil)
	nodeCpuUserTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "user_time_seconds"),
		"The cumulative CPU time which spends by user processes, when the node booting up.",
		[]string{"connection_uri"}, nil)
	nodeCpuIdleTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "idle_time_seconds"),
		"The cumulative idle CPU time, when the node booting up.",
		[]string{"connection_uri"}, nil)
	nodeCpuIoWaitTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "iowait_seconds"),
		"The cumulative I/O wait CPU time, when the node booting up.",
		[]string{"connection_uri"}, nil)
	nodeCpuUtilizationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "cpu_utilization"),
		"The CPU utilization. The usage value is in percent and 100% represents all CPUs on the server.",
		[]string{"connection_uri"}, nil)
	// 3.2 Memory stats
	nodeFreeMemoryBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "free_memory_bytes"),
		"Provides the free memory available on the Node.",
		[]string{"connection_uri"}, nil)
	// memory stats
	nodeMemstatsTotalBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "memstats_total_bytes"),
		"The total memory usage.",
		[]string{"connection_uri"}, nil)
	nodeMemstatsFreeBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "memstats_free_bytes"),
		"The free memory usage. On linux, this usage includes buffers and cached.",
		[]string{"connection_uri"}, nil)
	nodeMemstatsBuffersBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "memstats_buffers_bytes"),
		"The buffers memory usage.",
		[]string{"connection_uri"}, nil)
	nodeMemstatsCachedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "node", "memstats_cached_bytes"),
		"The cached memory usage.",
		[]string{"connection_uri"}, nil)
)

type Exporter struct {
	connection         *libvirt.Connect
	exportGuestMetrics bool
	uri                string
	domains            []string
}

func NewExporter(connectionUri string, exportGuest bool, domains []string) *Exporter {
	var conn *libvirt.Connect
	var err error
	if exportGuest {
		conn, err = libvirt.NewConnect(connectionUri)
	} else {
		conn, err = libvirt.NewConnectReadOnly(connectionUri)
	}
	if err != nil {
		log.Fatal(err)
	}
	caps, err := conn.GetCapabilities()
	if err == nil {
		fmt.Println(caps)
	}
	return &Exporter{conn, exportGuest, connectionUri, domains}
}

func (e *Exporter) Close() (int, error) {
	return e.connection.Close()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	var domains []libvirt.Domain
	var err error

	collectConnectInfo(e.connection, e.uri, ch)

	err = collectNodeCpuStats(e.connection, e.uri, ch)
	if err != nil {
		log.Printf("[ERROR] Failed to collect node CPU stats: %s\n", err)
	}

	err = collectNodeMemstats(e.connection, e.uri, ch)
	if err != nil {
		log.Printf("[ERROR] Failed to collect node memory stats: %s\n", err)
	}

	if len(e.domains) == 0 {
		domains, err = e.connection.ListAllDomains(0)
	} else {
		for _, domainName := range e.domains {
			domain, err := e.connection.LookupDomainByName(domainName)
			if err != nil {
				log.Printf("[WARN] Domain not found: %s. Ignoring...\n", domainName)
			} else {
				domains = append(domains, *domain)
			}
		}
	}
	if err != nil {
		log.Println(err)
		return
	}
	for _, domain := range domains {
		defer domain.Free()
		name, err := domain.GetName()
		if err != nil {
			log.Printf("[ERROR] Failed to get domain name: %s\n", err)
			continue
		}

		state, err := collectGeneralInfo(domain, name, e.uri, ch)
		if err != nil {
			log.Printf("[ERROR] Failed to collect domain info for domain %s: %s\n", name, err)
		}

		xmlDesc, err := domain.GetXMLDesc(0)
		if err != nil {
			log.Printf("[ERROR] Failed to get XML description for domain %s: %s\n", name, err)
		} else {
			xmlDoc, err := xmlquery.Parse(strings.NewReader(xmlDesc))
			if err != nil {
				log.Printf("[ERROR] Failed to parse XML description for domain %s: %s\n", name, err)
			} else {
				collectBlockInfoAndStats(domain, name, e.uri, state, xmlDoc, ch)
				collectInterfaceStats(domain, name, e.uri, xmlDoc, ch)
			}
		}

		if state != libvirt.DOMAIN_RUNNING {
			continue
		}

		err = collectCpuStats(domain, name, e.uri, ch)
		if err != nil {
			log.Printf("[ERROR] Failed to collect CPU statistics for domain %s: %s\n", name, err)
		}

		err = collectMemoryStats(domain, name, e.uri, ch)
		if err != nil {
			log.Printf("[ERROR] Failed to collect memory statistics for domain %s: %s\n", name, err)
		}

		err = collectDiskErrors(domain, name, e.uri, ch)
		if err != nil {
			log.Printf("[ERROR] Failed to collect disk errors for domain %s: %s\n", name, err)
		}

		if e.exportGuestMetrics {
			err = collectGuestInfo(domain, name, e.uri, ch)
			if err != nil {
				log.Printf("[ERROR] Failed to collect guest info for domain %s: %s\n", name, err)
			}
			err = collectFsInfo(domain, name, e.uri, ch)
			if err != nil {
				log.Printf("[ERROR] Failed to collect FS info for domain %s: %s\n", name, err)
			}
		}
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// General info
	ch <- infoDesc
	ch <- cpuCountDesc
	ch <- maxMemoryBytesDesc
	ch <- usedMemoryBytesDesc
	// CPU stats
	ch <- cpuSecondsTotalDesc
	ch <- cpuSystemSecondsTotalDesc
	ch <- cpuUserSecondsTotalDesc
	// Memory stats
	ch <- memstatsSwapInBytesDesc
	ch <- memstatsSwapOutBytesDesc
	ch <- memstatsMajorFaultsTotalDesc
	ch <- memstatsMinorFaultsTotalDesc
	ch <- memstatsUnusedBytesDesc
	ch <- memstatsAvailableBytesDesc
	ch <- memstatsUsableBytesDesc
	ch <- memstatsActualBalloonBytesDesc
	ch <- memstatsRssBytesDesc
	ch <- memstatsLastUpdateSecondsDesc
	ch <- memstatsDiskCachesBytes
	ch <- memstatsHugetblPgallocTotalDesc
	ch <- memstatsHugetblPgfailTotalDesc
	// Block info
	ch <- blockAllocationBytesDesc
	ch <- blockCapacityBytesDesc
	ch <- blockPhysicalBytesDesc
	// Block stats
	ch <- blockReadRequestsTotalDesc
	ch <- blockReadBytesDesc
	ch <- blockWriteRequestsTotalDesc
	ch <- blockWriteBytesDesc
	ch <- blockErrorsTotalDesc
	// Disk errors
	ch <- diskErrorInfoDesc
	// FS info
	ch <- fsInfoDesc
	// Interface stats
	ch <- ifstatsRxBytesDesc
	ch <- ifstatsRxDropTotalDesc
	ch <- ifstatsRxErrorsTotalDesc
	ch <- ifstatsRxPacketsTotalDesc
	ch <- ifstatsTxBytesDesc
	ch <- ifstatsTxDropTotalDesc
	ch <- ifstatsTxErrorsTotalDesc
	ch <- ifstatsTxPacketsTotalDesc
	// Guest info
	// Users
	ch <- guestActiveUsersTotalDesc
	// OS
	ch <- guestOsInfoDesc
	// Timezone
	ch <- guestTimezoneOffsetDesc
	// File System
	ch <- guestFsTotalDesc
	ch <- guestFsInfoDesc
	ch <- guestFsSizeBytesDesc
	ch <- guestFsUsedBytesDesc
	ch <- guestFsDisksTotalDesc
	ch <- guestFsDiskInfoDesc
	// Disks
	ch <- guestDisksTotalDesc
	ch <- guestDiskInfoDesc
	ch <- guestDiskDependencyCountDesc
	ch <- guestHostnameInfoDesc
	// Interfaces
	ch <- guestIfacesTotalDesc
	ch <- guestIfaceInfoDesc
	ch <- guestIfaceAddrTotalDesc
	ch <- guestIfaceAddrInfoDesc

	// Connect info
	ch <- connectInfoDesc
	// Node CPU stats
	ch <- nodeCpuIdleTimeDesc
	ch <- nodeCpuIoWaitTimeDesc
	ch <- nodeCpuKernelTimeDesc
	ch <- nodeCpuUserTimeDesc
	ch <- nodeCpuUtilizationDesc
	// Node free memory
	ch <- nodeFreeMemoryBytesDesc
	// Node memstats
	ch <- nodeMemstatsBuffersBytesDesc
	ch <- nodeMemstatsCachedBytesDesc
	ch <- nodeMemstatsFreeBytesDesc
	ch <- nodeMemstatsTotalBytesDesc
}

func collectGeneralInfo(domain libvirt.Domain, name string, uri string, ch chan<- prometheus.Metric) (libvirt.DomainState, error) {
	// TODO: Consider excluding domain ID from metric labels. When VM is shutoff, GetID() returns an error.
	id, err := domain.GetID()
	if err != nil {
		log.Printf("[ERROR] Failed to get id for domain %s: %s\n", name, err)
		id = 0
	}
	// get domain info.
	// See: https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainGetInfo
	info, err := domain.GetInfo()
	if err != nil {
		return 0, err
	}

	idString := strconv.FormatUint(uint64(id), 10)

	ch <- prometheus.MustNewConstMetric(infoDesc,
		prometheus.GaugeValue, 1, idString, name, domainStateToString(info.State), uri)
	ch <- prometheus.MustNewConstMetric(cpuCountDesc,
		prometheus.GaugeValue, float64(info.NrVirtCpu), uri, name)
	ch <- prometheus.MustNewConstMetric(maxMemoryBytesDesc,
		prometheus.GaugeValue, float64(info.MaxMem)*1024.0, uri, name)
	ch <- prometheus.MustNewConstMetric(usedMemoryBytesDesc,
		prometheus.GaugeValue, float64(info.Memory)*1024.0, uri, name)

	return info.State, nil
}

func collectCpuStats(domain libvirt.Domain, name string, uri string, ch chan<- prometheus.Metric) error {
	// get aggregated CPU statistics.
	// See: https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainGetCPUStats
	stats, err := domain.GetCPUStats(-1, 1, 0)
	if err != nil {
		return err
	}

	// values are in nanoseconds. Convert to seconds first.
	cpuTime := float64(stats[0].CpuTime) / 1000000000.0
	systemTime := float64(stats[0].SystemTime) / 1000000000.0
	userTime := float64(stats[0].UserTime) / 1000000000.0

	ch <- prometheus.MustNewConstMetric(cpuSecondsTotalDesc,
		prometheus.CounterValue, cpuTime, uri, name)
	ch <- prometheus.MustNewConstMetric(cpuSystemSecondsTotalDesc,
		prometheus.CounterValue, systemTime, uri, name)
	ch <- prometheus.MustNewConstMetric(cpuUserSecondsTotalDesc,
		prometheus.CounterValue, userTime, uri, name)

	return nil
}

func collectMemoryStats(domain libvirt.Domain, name string, uri string, ch chan<- prometheus.Metric) error {
	stats, err := domain.MemoryStats(uint32(libvirt.DOMAIN_MEMORY_STAT_NR), 0)
	if err != nil {
		return err
	}
	for _, stat := range stats {
		switch stat.Tag {
		case int32(libvirt.DOMAIN_MEMORY_STAT_SWAP_IN):
			ch <- prometheus.MustNewConstMetric(memstatsSwapInBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_SWAP_OUT):
			ch <- prometheus.MustNewConstMetric(memstatsSwapOutBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_MAJOR_FAULT):
			ch <- prometheus.MustNewConstMetric(memstatsMajorFaultsTotalDesc,
				prometheus.CounterValue, float64(stat.Val), uri, name)
		case int32(libvirt.DOMAIN_MEMORY_STAT_MINOR_FAULT):
			ch <- prometheus.MustNewConstMetric(memstatsMinorFaultsTotalDesc,
				prometheus.CounterValue, float64(stat.Val), uri, name)
		case int32(libvirt.DOMAIN_MEMORY_STAT_UNUSED):
			ch <- prometheus.MustNewConstMetric(memstatsUnusedBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_AVAILABLE):
			ch <- prometheus.MustNewConstMetric(memstatsAvailableBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_USABLE):
			ch <- prometheus.MustNewConstMetric(memstatsUsableBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_ACTUAL_BALLOON):
			ch <- prometheus.MustNewConstMetric(memstatsActualBalloonBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_RSS):
			ch <- prometheus.MustNewConstMetric(memstatsRssBytesDesc,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // Kib -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_LAST_UPDATE):
			ch <- prometheus.MustNewConstMetric(memstatsLastUpdateSecondsDesc,
				prometheus.CounterValue, float64(stat.Val), uri, name)
		case int32(libvirt.DOMAIN_MEMORY_STAT_DISK_CACHES):
			ch <- prometheus.MustNewConstMetric(memstatsDiskCachesBytes,
				prometheus.GaugeValue, float64(stat.Val)*1024.0, uri, name) // KiB -> Bytes
		case int32(libvirt.DOMAIN_MEMORY_STAT_HUGETLB_PGALLOC):
			ch <- prometheus.MustNewConstMetric(memstatsHugetblPgallocTotalDesc,
				prometheus.CounterValue, float64(stat.Val), uri, name)
		case int32(libvirt.DOMAIN_MEMORY_STAT_HUGETLB_PGFAIL):
			ch <- prometheus.MustNewConstMetric(memstatsHugetblPgfailTotalDesc,
				prometheus.CounterValue, float64(stat.Val), uri, name)
		default:
			log.Printf("[ERROR] Unsupported memory stat flag: %d", stat.Tag)
		}
	}
	return nil
}

func collectBlockInfoAndStats(domain libvirt.Domain, name string, uri string, state libvirt.DomainState, xmlDoc *xmlquery.Node, ch chan<- prometheus.Metric) {
	xpath := "//domain/devices/disk/target/@dev"
	for _, node := range xmlquery.Find(xmlDoc, xpath) {
		disk := node.InnerText()
		info, err := domain.GetBlockInfo(disk, 0)
		if err != nil {
			log.Printf("[ERROR] Failed to get block info for disk %s on domain %s: %s\n", disk, name, err)
		} else {
			ch <- prometheus.MustNewConstMetric(blockAllocationBytesDesc,
				prometheus.GaugeValue, float64(info.Allocation), uri, name, disk)
			ch <- prometheus.MustNewConstMetric(blockCapacityBytesDesc,
				prometheus.GaugeValue, float64(info.Capacity), uri, name, disk)
			ch <- prometheus.MustNewConstMetric(blockPhysicalBytesDesc,
				prometheus.GaugeValue, float64(info.Physical), uri, name, disk)
		}
		if state == libvirt.DOMAIN_RUNNING {
			stats, err := domain.BlockStats(disk)
			if err != nil {
				log.Printf("[ERROR] Failed to get block stats for disk %s on domain %s: %s\n", disk, name, err)
				continue
			}
			ch <- prometheus.MustNewConstMetric(blockReadBytesDesc,
				prometheus.CounterValue, float64(stats.RdBytes), uri, name, disk)
			ch <- prometheus.MustNewConstMetric(blockReadRequestsTotalDesc,
				prometheus.CounterValue, float64(stats.RdReq), uri, name, disk)
			ch <- prometheus.MustNewConstMetric(blockWriteBytesDesc,
				prometheus.CounterValue, float64(stats.WrBytes), uri, name, disk)
			ch <- prometheus.MustNewConstMetric(blockWriteRequestsTotalDesc,
				prometheus.CounterValue, float64(stats.WrReq), uri, name, disk)
			ch <- prometheus.MustNewConstMetric(blockErrorsTotalDesc,
				prometheus.CounterValue, float64(stats.Errs), uri, name, disk)
		}
	}
}

func collectInterfaceStats(domain libvirt.Domain, name string, uri string, xmlDoc *xmlquery.Node, ch chan<- prometheus.Metric) {
	xpath := "//domain/devices/interface/target/@dev"
	for _, node := range xmlquery.Find(xmlDoc, xpath) {
		iface := node.InnerText()
		stats, err := domain.InterfaceStats(iface)
		if err != nil {
			log.Printf("[ERROR] Failed to get interface stats for %s on domain %s: %s\n", iface, name, err)
			continue
		}

		ch <- prometheus.MustNewConstMetric(ifstatsRxBytesDesc,
			prometheus.CounterValue, float64(stats.RxBytes), uri, name, iface)
		ch <- prometheus.MustNewConstMetric(ifstatsRxDropTotalDesc,
			prometheus.CounterValue, float64(stats.RxDrop), uri, name, iface)
		ch <- prometheus.MustNewConstMetric(ifstatsRxErrorsTotalDesc,
			prometheus.CounterValue, float64(stats.RxErrs), uri, name, iface)
		ch <- prometheus.MustNewConstMetric(ifstatsRxPacketsTotalDesc,
			prometheus.CounterValue, float64(stats.RxPackets), uri, name, iface)
		ch <- prometheus.MustNewConstMetric(ifstatsTxBytesDesc,
			prometheus.CounterValue, float64(stats.TxBytes), uri, name, iface)
		ch <- prometheus.MustNewConstMetric(ifstatsTxDropTotalDesc,
			prometheus.CounterValue, float64(stats.TxDrop), uri, name, iface)
		ch <- prometheus.MustNewConstMetric(ifstatsTxErrorsTotalDesc,
			prometheus.CounterValue, float64(stats.TxPackets), uri, name, iface)
	}
}

func collectDiskErrors(domain libvirt.Domain, name string, uri string, ch chan<- prometheus.Metric) error {
	diskErrors, err := domain.GetDiskErrors(0)
	if err != nil {
		return err
	}
	for _, diskError := range diskErrors {
		if diskError.Disk != "" {
			ch <- prometheus.MustNewConstMetric(diskErrorInfoDesc,
				prometheus.GaugeValue, 1, uri, name, diskError.Disk, domainDiskErrorCodeToString(diskError.Error))
		}
	}
	return nil
}

func collectFsInfo(domain libvirt.Domain, name string, uri string, ch chan<- prometheus.Metric) error {
	fsInfos, err := domain.GetFSInfo(0)
	if err != nil {
		return err
	}
	for _, fsInfo := range fsInfos {
		ch <- prometheus.MustNewConstMetric(fsInfoDesc,
			prometheus.GaugeValue, 1, uri, name, fsInfo.MountPoint, fsInfo.Name, fsInfo.FSType)
	}
	return nil
}

func collectGuestInfo(domain libvirt.Domain, name string, uri string, ch chan<- prometheus.Metric) error {
	info, err := domain.GetGuestInfo(0, 0)
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(guestActiveUsersTotalDesc,
		prometheus.GaugeValue, float64(len(info.Users)), uri, name)

	ch <- prometheus.MustNewConstMetric(guestOsInfoDesc,
		prometheus.GaugeValue, 1, uri, name, info.OS.Name, info.OS.Version,
		info.OS.KernelRelease, info.OS.KernelVersion, info.OS.Machine, info.OS.Variant)

	ch <- prometheus.MustNewConstMetric(guestTimezoneOffsetDesc,
		prometheus.GaugeValue, float64(info.TimeZone.Offset), uri, name, info.TimeZone.Name)

	ch <- prometheus.MustNewConstMetric(guestFsTotalDesc,
		prometheus.GaugeValue, float64(len(info.FileSystems)), uri, name)
	for _, fs := range info.FileSystems {
		ch <- prometheus.MustNewConstMetric(guestFsInfoDesc,
			prometheus.GaugeValue, 1, uri, name, fs.Name, fs.MountPoint, fs.FSType)
	}

	ch <- prometheus.MustNewConstMetric(guestFsDisksTotalDesc,
		prometheus.GaugeValue, float64(len(info.Disks)), uri, name)
	for _, disk := range info.Disks {
		ch <- prometheus.MustNewConstMetric(guestDiskInfoDesc,
			prometheus.GaugeValue, 1, uri, name, disk.Name, strconv.FormatBool(disk.Partition), disk.Alias, disk.GuestAlias)
	}

	ch <- prometheus.MustNewConstMetric(guestHostnameInfoDesc,
		prometheus.GaugeValue, 1, uri, name, info.Hostname)

	ch <- prometheus.MustNewConstMetric(guestIfacesTotalDesc,
		prometheus.GaugeValue, float64(len(info.Interfaces)), uri, name)
	for _, iface := range info.Interfaces {
		ch <- prometheus.MustNewConstMetric(guestIfaceInfoDesc,
			prometheus.GaugeValue, 1, uri, name, iface.Name, iface.Hwaddr)
		ch <- prometheus.MustNewConstMetric(guestIfaceAddrTotalDesc,
			prometheus.GaugeValue, float64(len(iface.Addrs)), uri, name, iface.Name)
		for _, addr := range iface.Addrs {
			ch <- prometheus.MustNewConstMetric(guestIfaceAddrInfoDesc,
				prometheus.GaugeValue, 1, uri, name, iface.Name, addr.Type,
				addr.Addr, strconv.FormatUint(uint64(addr.Prefix), 10))
		}
	}
	return nil
}

func collectConnectInfo(conn *libvirt.Connect, uri string, ch chan<- prometheus.Metric) {
	hostname, err := conn.GetHostname()
	if err != nil {
		log.Printf("[ERROR] Failed to get hostname: %s\n", err)
		hostname = ""
	}
	version, err := conn.GetLibVersion()
	if err != nil {
		log.Printf("[ERROR] Failed to get lib version: %s\n", err)
		version = 0
	}
	hypervType, err := conn.GetType()
	if err != nil {
		log.Printf("[ERROR] Failed to get type: %s\n", err)
		hypervType = ""
	}
	encrypted, err := conn.IsEncrypted()
	if err != nil {
		log.Printf("[ERROR] Failed to check if is encrypted: %s\n", err)
		encrypted = false
	}
	secure, err := conn.IsSecure()
	if err != nil {
		log.Printf("[ERROR] Failed to check if is secure: %s\n", err)
		secure = false
	}
	ch <- prometheus.MustNewConstMetric(connectInfoDesc,
		prometheus.GaugeValue, 1, uri, hostname,
		strconv.FormatUint(uint64(version), 10), hypervType,
		strconv.FormatBool(encrypted), strconv.FormatBool(secure))
}

func collectNodeCpuStats(conn *libvirt.Connect, uri string, ch chan<- prometheus.Metric) error {
	stats, err := conn.GetCPUStats(int(libvirt.NODE_CPU_STATS_ALL_CPUS), 0)
	if err != nil {
		return err
	}

	kernelTime := float64(stats.Kernel) / 1000000000.0
	userTime := float64(stats.User) / 1000000000.0
	idleTime := float64(stats.Idle) / 1000000000.0
	iowaitTime := float64(stats.Iowait) / 1000000000.0
	cpuUtilization := float64(stats.Utilization) / 100.0

	ch <- prometheus.MustNewConstMetric(nodeCpuKernelTimeDesc,
		prometheus.CounterValue, kernelTime, uri)
	ch <- prometheus.MustNewConstMetric(nodeCpuUserTimeDesc,
		prometheus.CounterValue, userTime, uri)
	ch <- prometheus.MustNewConstMetric(nodeCpuIdleTimeDesc,
		prometheus.CounterValue, idleTime, uri)
	ch <- prometheus.MustNewConstMetric(nodeCpuIoWaitTimeDesc,
		prometheus.CounterValue, iowaitTime, uri)
	ch <- prometheus.MustNewConstMetric(nodeCpuUtilizationDesc,
		prometheus.GaugeValue, cpuUtilization, uri)
	return nil
}

func collectNodeMemstats(conn *libvirt.Connect, uri string, ch chan<- prometheus.Metric) error {
	freeMem, err := conn.GetFreeMemory()
	if err != nil {
		log.Printf("[ERROR] Failed to get node free memory: %s", err)
	} else {
		ch <- prometheus.MustNewConstMetric(nodeFreeMemoryBytesDesc,
			prometheus.GaugeValue, float64(freeMem), uri)
	}
	stats, err := conn.GetMemoryStats(libvirt.NODE_MEMORY_STATS_ALL_CELLS, 0)
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(nodeMemstatsTotalBytesDesc,
		prometheus.GaugeValue, float64(stats.Total)*1024.0, uri)
	ch <- prometheus.MustNewConstMetric(nodeMemstatsFreeBytesDesc,
		prometheus.GaugeValue, float64(stats.Free)*1024.0, uri)
	ch <- prometheus.MustNewConstMetric(nodeMemstatsBuffersBytesDesc,
		prometheus.GaugeValue, float64(stats.Buffers)*1024.0, uri)
	ch <- prometheus.MustNewConstMetric(nodeMemstatsCachedBytesDesc,
		prometheus.GaugeValue, float64(stats.Cached)*1024.0, uri)
	return nil
}

func domainDiskErrorCodeToString(code libvirt.DomainDiskErrorCode) string {
	switch code {
	case libvirt.DOMAIN_DISK_ERROR_NONE:
		return "NONE"
	case libvirt.DOMAIN_DISK_ERROR_UNSPEC:
		return "UNSPEC"
	case libvirt.DOMAIN_DISK_ERROR_NO_SPACE:
		return "NO_SPACE"
	default:
		log.Printf("[ERROR] Unsupported disk error code: %d\n", code)
	}
	return ""
}

func domainStateToString(state libvirt.DomainState) string {
	switch state {
	case libvirt.DOMAIN_NOSTATE:
		return "NOSTATE"
	case libvirt.DOMAIN_RUNNING:
		return "RUNNING"
	case libvirt.DOMAIN_BLOCKED:
		return "BLOCKED"
	case libvirt.DOMAIN_PAUSED:
		return "PAUSED"
	case libvirt.DOMAIN_SHUTDOWN:
		return "SHUTDOWN"
	case libvirt.DOMAIN_SHUTOFF:
		return "SHUTOFF"
	case libvirt.DOMAIN_CRASHED:
		return "CRASHED"
	case libvirt.DOMAIN_PMSUSPENDED:
		return "PMSUSPENDED"
	default:
		log.Printf("[ERROR] Unsupported domain state: %d\n", state)
	}
	return ""
}
