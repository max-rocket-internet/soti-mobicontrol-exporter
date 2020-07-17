package main

import (
	"flag"
	"fmt"
	"github.com/max-rocket-internet/soti-mobicontrol-exporter/mobicontrol"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	log = logrus.New()

	serverStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "soti_mc",
		Subsystem: "servers",
		Name:      "status",
		Help:      "Status of SOTI MobiControl API servers by type",
	}, []string{
		"server_name",
		"type",
		"status",
	})

	serverVersion = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "soti_mc",
		Subsystem: "servers",
		Name:      "version",
		Help:      "Version of SOTI MobiControl servers",
	}, []string{
		"server_name",
		"version",
	})

	devicesAgentOnline = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "soti_mc",
		Subsystem: "devices",
		Name:      "agent_online",
		Help:      "Agent online status of SOTI MobiControl devices",
	}, []string{
		"online",
		"server_name",
		"cellular_carrier",
		"network_connection_type",
		"path",
		"path_split_1",
		"path_split_2",
		"path_split_3",
		"path_split_4",
		"path_split_5",
		"path_split_6",
	})

	devicesEvents = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "soti_mc",
		Subsystem: "devices",
		Name:      "events",
		Help:      "Events SOTI MobiControl devices in the last 60 minutes",
	}, []string{
		"event_type",
		"server_name",
		"cellular_carrier",
		"network_connection_type",
		"path",
		"path_split_1",
		"path_split_2",
		"path_split_3",
		"path_split_4",
		"path_split_5",
		"path_split_6",
	})

	devicesCellularSignalStrength = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "soti_mc",
		Subsystem: "devices",
		Name:      "cellular_signal_strength",
		Help:      "Cellular signal strength of SOTI MobiControl devices",
	}, []string{
		"server_name",
		"cellular_carrier",
		"network_connection_type",
		"path",
		"path_split_1",
		"path_split_2",
		"path_split_3",
		"path_split_4",
		"path_split_5",
		"path_split_6",
	})

	prometheusHandler = promhttp.Handler()
)

func init() {
	log.Formatter = new(logrus.JSONFormatter)
	log.Out = os.Stdout
	log.Level = logrus.InfoLevel

	if value, exists := os.LookupEnv("LOG_LEVEL"); exists {
		if value == "DEBUG" {
			log.Level = logrus.DebugLevel
		}
	}
}

func healthz(w http.ResponseWriter, r *http.Request) {
}

func getServerMetrics() {
	serverStatus.Reset()
	start := time.Now()
	servers := mobicontrol.GetServers()

	for _, server := range servers.DeploymentServers {
		serverStatus.WithLabelValues(server.Name, "deployment", server.Status).Inc()
		serverVersion.WithLabelValues(server.Name, servers.ProductVersion+"-"+servers.ProductVersionBuild).Set(1)
	}

	for _, server := range servers.ManagementServers {
		serverStatus.WithLabelValues(server.Name, "management", server.Status).Inc()
		serverVersion.WithLabelValues(server.Name, servers.ProductVersion+"-"+servers.ProductVersionBuild).Set(1)
	}

	log.Debug(fmt.Sprintf("Server metrics processed: %v servers in %v seconds", len(servers.DeploymentServers)+len(servers.ManagementServers), int(time.Since(start).Seconds())))
}

func getPathElements(path string) []string {
	paths := make([]string, 6)
	n := 0
	for i, p := range strings.Split(path, "\\") {
		if i >= len(paths) {
			log.Error("Path depth is higher than supported")
			return paths
		}
		if p != "" {
			paths[n] = p
			n++
		}
	}

	return paths
}

func convertTo64(ar []int) []float64 {
	newar := make([]float64, len(ar))
	var v int
	var i int
	for i, v = range ar {
		newar[i] = float64(v)
	}
	return newar
}

func getDeviceMetrics() {
	devicesAgentOnline.Reset()
	devicesEvents.Reset()
	start := time.Now()

	devices := mobicontrol.GetAllDevices()

	for _, device := range devices {
		paths := getPathElements(device.Path)

		networkConnectionType := fmt.Sprintf("%v", device.NetworkConnectionType)

		if device.IsAgentOnline {
			devicesAgentOnline.WithLabelValues("1", device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		} else {
			devicesAgentOnline.WithLabelValues("0", device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}

		if time.Since(device.EnrollmentTime).Seconds() < 3600 {
			devicesEvents.WithLabelValues("enrollment_time", device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}

		if time.Since(device.LastCheckInTime).Seconds() < 3600 {
			devicesEvents.WithLabelValues("last_check_in_time", device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}

		if time.Since(device.LastAgentConnectTime).Seconds() < 3600 {
			devicesEvents.WithLabelValues("last_agent_connect_time", device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}

		if time.Since(device.LastAgentDisconnectTime).Seconds() < 3600 {
			devicesEvents.WithLabelValues("last_agent_disconnect_time", device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}

		devicesCellularSignalStrength.WithLabelValues(device.ServerName, device.CellularCarrier, networkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Observe(float64(device.CellularSignalStrength))
	}

	log.Debug(fmt.Sprintf("Device metrics processed: %v devices in %v seconds", len(devices), int(time.Since(start).Seconds())))
}

func getPromMetrics() {
	getServerMetrics()
	getDeviceMetrics()
}

func sotiMcHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		getPromMetrics()
		prometheusHandler.ServeHTTP(w, r)
	}
}

func main() {
	debugMode := flag.Bool("debug", false, "Will run once and exit")
	flag.Parse()

	if *debugMode {
		getServerMetrics()
		getDeviceMetrics()
		os.Exit(0)
	}

	log.Info("soti-mobicontrol-exporter starting")
	http.HandleFunc("/healthz", healthz)
	http.HandleFunc("/metrics", sotiMcHandler())
	http.ListenAndServe(":9571", nil)
}
