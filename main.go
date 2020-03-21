package main

import (
	"flag"
	"github.com/shibumi/cifs-exporter/cifs"
	"log"
	"os"
	"path/filepath"
	//"github.com/prometheus/client_golang/prometheus"
)

var version, commit, date string

func main() {
	//listenAddr := flag.String("web.listen-address", ":9812", "Address to listen on for web interface and telemetry.")
	//metricsPath := flag.String("web.telemetry-path", "/metrics", "A path under which to expose metrics.")
	appVersion := flag.Bool("version", false, "Display version information")
	flag.Parse()
	if *appVersion {
		println(filepath.Base(os.Args[0]), version, commit, date)
		os.Exit(0)
	}
	stats, _ := cifs.NewClientStats()
	log.Println(stats)

}
