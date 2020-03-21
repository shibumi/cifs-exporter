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
}
