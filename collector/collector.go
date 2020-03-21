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

}
