package collector

import (
	"github.com/prometheus/client_golang/prometheus"
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

}
