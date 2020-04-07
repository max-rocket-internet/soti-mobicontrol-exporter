package main

import (
	"github.com/max-rocket-internet/soti-mobicontrol-exporter/mobicontrol"
	"fmt"
	"github.com/montanaflynn/stats"
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

	devicesCellularSignalStrength = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "soti_mc",
		Subsystem: "devices",
		Name:      "cellular_signal_strength_median",
		Help:      "Average cellular signal strength of SOTI MobiControl devices",
	}, []string{
		"cellular_carrier",
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

	servers := mobicontrol.GetServers()

	for _, server := range servers.DeploymentServers {
		serverStatus.WithLabelValues(server.Name, "deployment", server.Status).Inc()
		serverVersion.WithLabelValues(server.Name, servers.ProductVersion + "-" + servers.ProductVersionBuild).Set(1)
	}

	for _, server := range servers.ManagementServers {
		serverStatus.WithLabelValues(server.Name, "management", server.Status).Inc()
		serverVersion.WithLabelValues(server.Name, servers.ProductVersion + "-" + servers.ProductVersionBuild).Set(1)
	}

	log.Debug("Server metrics processed")
}

func getPathElements(path string) []string {
	paths := make([]string, 6)
	n := 0
	for i, p := range strings.Split(path, "\\") {
		if i >= len(paths) {
			log.Debug("Path depth is higher than supported")
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
	devicesCellularSignalStrength.Reset()

	start := time.Now()

	devices := mobicontrol.GetDevices()

	deviceCellularSignalStrengths := make(map[string][]int)

	for _, device := range devices {
		paths := getPathElements(device.Path)

		// device agent online status
		if device.IsAgentOnline {
			devicesAgentOnline.WithLabelValues("1", device.ServerName, device.CellularCarrier, device.NetworkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		} else {
			devicesAgentOnline.WithLabelValues("0", device.ServerName, device.CellularCarrier, device.NetworkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}

		// device events
		enrollment_time, err := time.Parse("2006-01-02T15:04:05Z07:00", device.EnrollmentTime)
		if time.Since(enrollment_time).Seconds() < 3600 {
			devicesEvents.WithLabelValues("enrollment_time", device.ServerName, device.CellularCarrier, device.NetworkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}
		if err != nil {
			log.Fatal(fmt.Sprintf("Error in parsing timestamp: %v", err))
			continue
		}

		last_check_in_time, err := time.Parse("2006-01-02T15:04:05Z07:00", device.LastCheckInTime)
		if time.Since(last_check_in_time).Seconds() < 3600 {
			devicesEvents.WithLabelValues("last_check_in_time", device.ServerName, device.CellularCarrier, device.NetworkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}
		if err != nil {
			log.Fatal(fmt.Sprintf("Error in parsing timestamp: %v", err))
			continue
		}

		last_agent_connect_time, err := time.Parse("2006-01-02T15:04:05Z07:00", device.LastAgentConnectTime)
		if time.Since(last_agent_connect_time).Seconds() < 3600 {
			devicesEvents.WithLabelValues("last_agent_connect_time", device.ServerName, device.CellularCarrier, device.NetworkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}
		if err != nil {
			log.Fatal(fmt.Sprintf("Error in parsing timestamp: %v", err))
			continue
		}

		last_agent_disconnect_time, err := time.Parse("2006-01-02T15:04:05Z07:00", device.LastAgentDisconnectTime)
		if time.Since(last_agent_disconnect_time).Seconds() < 3600 {
			devicesEvents.WithLabelValues("last_agent_disconnect_time", device.ServerName, device.CellularCarrier, device.NetworkConnectionType, device.Path, paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]).Inc()
		}
		if err != nil {
			log.Fatal(fmt.Sprintf("Error in parsing timestamp: %v", err))
			continue
		}

		// device cellular signal strength
		if _, ok := deviceCellularSignalStrengths[device.CellularCarrier]; !ok {
			deviceCellularSignalStrengths[device.CellularCarrier] = make([]int, 0)
		}
		deviceCellularSignalStrengths[device.CellularCarrier] = append(deviceCellularSignalStrengths[device.CellularCarrier], device.CellularSignalStrength)
	}

	for k, v := range deviceCellularSignalStrengths {
		if k == "" {
			continue
		}
		median, err := stats.Median(convertTo64(v))
		if err != nil {
			log.Fatal(fmt.Sprintf("Error calculating median: %v", err))
			continue
		}
		devicesCellularSignalStrength.WithLabelValues(k).Set(median)
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
	log.Info("soti-mobicontrol-exporter starting")
	http.HandleFunc("/healthz", healthz)
	http.HandleFunc("/metrics", sotiMcHandler())
	http.ListenAndServe(":9571", nil)
}
