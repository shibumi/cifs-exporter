package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shibumi/cifs-exporter/cifs"
	"log"
	"sync"
)

type CIFSCollector struct {
	metrics map[string]*prometheus.Desc
	mutex   sync.Mutex
}

// NewCIFSCollector creates a CIFSCollector
func NewCIFSCollector() *CIFSCollector {
	return &CIFSCollector{
		metrics: map[string]*prometheus.Desc{
			"cifs_total_cifs_sessions":        prometheus.NewDesc("cifs_total_cifs_sessions", "Total CIFS sessions", nil, nil),
			"cifs_total_unique_mount_targets": prometheus.NewDesc("cifs_total_unique_mount_targets", "Total unique mount targets", nil, nil),
			"cifs_total_requests":             prometheus.NewDesc("cifs_total_requests", "Total requests", nil, nil),
			"cifs_total_buffer":               prometheus.NewDesc("cifs_total_buffer", "Total buffer", nil, nil),
			"cifs_total_small_requests":       prometheus.NewDesc("cifs_total_small_requests", "Total small requests", nil, nil),
			"cifs_total_small_buffer":         prometheus.NewDesc("cifs_total_small_buffer", "Total small buffer", nil, nil),
			"cifs_total_op":                   prometheus.NewDesc("cifs_total_op", "Total op", nil, nil),
			"cifs_total_session":              prometheus.NewDesc("cifs_total_session", "Total session", nil, nil),
			"cifs_total_share_reconnects":     prometheus.NewDesc("cifs_total_share_reconnects", "Total share reconnects", nil, nil),
			"cifs_total_max_op":               prometheus.NewDesc("cifs_total_max_op", "Total max op", nil, nil),
			"cifs_total_at_once":              prometheus.NewDesc("cifs_total_at_once", "Total operations at once", nil, nil),
		},
	}
}

// Describe outputs metrics descriptions.
func (c *CIFSCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.metrics {
		ch <- m
	}
}

func (c *CIFSCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	stats, err := cifs.NewClientStats()
	if err != nil {
		log.Println(err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_cifs_sessions"], prometheus.GaugeValue, float64(stats.Header.CIFSSession))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_unique_mount_targets"], prometheus.GaugeValue, float64(stats.Header.Targets))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_requests"], prometheus.GaugeValue, float64(stats.Header.SMBReq))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_buffer"], prometheus.GaugeValue, float64(stats.Header.SMBBuf))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_small_requests"], prometheus.GaugeValue, float64(stats.Header.SMBSmallReq))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_small_buffer"], prometheus.GaugeValue, float64(stats.Header.SMBSmallBuf))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_op"], prometheus.GaugeValue, float64(stats.Header.Op))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_session"], prometheus.GaugeValue, float64(stats.Header.Session))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_share_reconnects"], prometheus.GaugeValue, float64(stats.Header.ShareReconnects))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_max_op"], prometheus.GaugeValue, float64(stats.Header.MaxOp))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_at_once"], prometheus.GaugeValue, float64(stats.Header.AtOnce))

	// len(SMB1/2 metrics) = 22
	// len(SMB3 metrics) = 39
	for _, block := range stats.Blocks {
		l := prometheus.Labels{"server": block.Server, "share": block.Share}
		if len(block.Metrics) == 22 {
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_smb", "Total SMB", nil, l), prometheus.GaugeValue, float64(block.Metrics[0]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks", "Total oplock breaks", nil, l), prometheus.GaugeValue, float64(block.Metrics[1]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads", "Total reads", nil, l), prometheus.GaugeValue, float64(block.Metrics[2]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_read_bytes", "Total read bytes", nil, l), prometheus.GaugeValue, float64(block.Metrics[3]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes", "Total writes", nil, l), prometheus.GaugeValue, float64(block.Metrics[4]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_write_bytes", "Total write bytes", nil, l), prometheus.GaugeValue, float64(block.Metrics[5]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes", "Total flushes", nil, l), prometheus.GaugeValue, float64(block.Metrics[6]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks", "Total locks", nil, l), prometheus.GaugeValue, float64(block.Metrics[7]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_hardlinks", "Total hardlinks", nil, l), prometheus.GaugeValue, float64(block.Metrics[8]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_symlinks", "Total symlinks", nil, l), prometheus.GaugeValue, float64(block.Metrics[9]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_opens", "Total opens", nil, l), prometheus.GaugeValue, float64(block.Metrics[10]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes", "Total closes", nil, l), prometheus.GaugeValue, float64(block.Metrics[11]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_deletes", "Total deletes", nil, l), prometheus.GaugeValue, float64(block.Metrics[12]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_posix_opens", "Total posix opens", nil, l), prometheus.GaugeValue, float64(block.Metrics[13]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_posix_mkdirs", "Total posix mkdirs", nil, l), prometheus.GaugeValue, float64(block.Metrics[14]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_mkdirs", "Total mkdirs", nil, l), prometheus.GaugeValue, float64(block.Metrics[15]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_rmdirs", "Total rmdirs", nil, l), prometheus.GaugeValue, float64(block.Metrics[16]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_renames", "Total renames", nil, l), prometheus.GaugeValue, float64(block.Metrics[17]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_t2_renames", "Total T2 renames", nil, l), prometheus.GaugeValue, float64(block.Metrics[18]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_find_first", "Total find first", nil, l), prometheus.GaugeValue, float64(block.Metrics[19]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_find_next", "Total find next", nil, l), prometheus.GaugeValue, float64(block.Metrics[20]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_find_close", "Total find close", nil, l), prometheus.GaugeValue, float64(block.Metrics[21]))
		} else if len(block.Metrics) == 39 {
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_smb", "Total SMB", nil, l), prometheus.GaugeValue, float64(block.Metrics[0]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_negotiates_sent", "Total negotiates sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[1]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_negotiates_failed", "Total negotiates failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[2]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_session_setups_sent", "Total session setups sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[3]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_session_setups_failed", "Total session setups fauled", nil, l), prometheus.GaugeValue, float64(block.Metrics[4]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_logoffs_sent", "Total logoffs sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[5]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_logoffs_failed", "Total logoffs failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[6]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_connects_sent", "Total tree_connects sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[7]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_connects_failed", "Total tree_connects failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[8]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_disconnects_sent", "Total tree_disconnects sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[9]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_disconnects_failed", "Total tree_disconnects failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[10]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_creates_sent", "Total creates sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[11]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_creates_failed", "Total creates failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[12]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes_sent", "Total closes sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[13]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes_failed", "Total closes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[14]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes_sent", "Total flushes sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[15]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes_failed", "Total flushes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[16]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads_sent", "Total reads sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[17]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads_failed", "Total reads failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[18]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes_sent", "Total writes sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[19]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes_failed", "Total writes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[20]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks_sent", "Total locks sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[21]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks_failed", "Total locks failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[22]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_ioctls_sent", "Total ioctls sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[23]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_ioctls_failed", "Total ioctls failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[24]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_cancels_sent", "Total cancels sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[25]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_cancels_failed", "Total cancels failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[26]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_echos_sent", "Total echos sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[27]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_echos_failed", "Total echos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[28]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_directories_sent", "Total query_directories sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[29]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_directories_failed", "Total query_directories failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[30]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_change_notifies_sent", "Total change_notifies sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[31]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_change_notifies_failed", "Total change_notifies failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[32]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_infos_sent", "Total query_infos sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[33]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_infos_failed", "Total query_infos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[34]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_set_infos_sent", "Total set_infos sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[35]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_set_infos_failed", "Total set_infos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[36]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks_sent", "Total oplocks breaks sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[37]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks_failed", "Total oplocks breaks failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[38]))
		}
	}
}
