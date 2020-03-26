package mobicontrol

import (
	"net/http"
	"time"
  "os"
	"fmt"
  "encoding/json"
  "encoding/base64"
  "net/url"
  "strconv"
  "strings"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type mobiControlToken struct {
	Expires     int       `json:"expires_in"`
  CreatedAt   time.Time `json:"created_at"`
  TokenType   string    `json:"token_type"`
  AccessToken string    `json:"access_token"`
}

type MobiControlServer struct {
  Name   string
  Status string
}

type mobiControlServerStatus struct {
  ProductVersion      string
  ProductVersionBuild string
  DeploymentServers   []MobiControlServer
  ManagementServers   []MobiControlServer
}

type mobiControlDevice struct {
  DeviceId                string
  CellularCarrier         string
  CellularSignalStrength  int
  EnrollmentTime          string
  LastCheckInTime         string
  LastAgentConnectTime    string
  LastAgentDisconnectTime string
  NetworkConnectionType   string
  IsAgentOnline           bool
  Path                    string
  ServerName              string
}

type Config struct {
		apiBase         string
		clientId        string
		clientSecret    string
		username        string
		password        string
		mobicontrolHost string
		logLevel        string
}

func newConfig() *Config {
  return &Config {
		clientId:        getEnv("CLIENT_ID"),
		clientSecret:    getEnv("CLIENT_SECRET"),
		username:        getEnv("USERNAME"),
		password:        getEnv("PASSWORD"),
		mobicontrolHost: getEnv("MOBICONTROL_HOST"),
    apiBase:         getEnv("API_PREFIX", "/MobiControl/api"),
		logLevel:        getEnv("LOG_LEVEL", "INFO"),
  }
}

func getEnv(params...string) string {
  if value, exists := os.LookupEnv(params[0]); exists {
		return value
  } else if len(params) > 1 {
		return params[1]
	} else {
		log.Fatal(fmt.Sprintf("Environment variable %s must be set", params[0]))
		return ""
	}
}

var (
	httpUserAgent = "github/max-rocket-internet/soti-mobicontrol-exporter/1.0"

	client = &http.Client{}

  token = mobiControlToken{}

	conf = newConfig()

	apiLatency = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "soti_mc",
    Subsystem: "api",
		Name:      "latency",
		Help:      "Latency of SOTI MobiControl API endpoints",
	}, []string{
		"endpoint",
	})
)

func init() {
  log.SetFormatter(&log.JSONFormatter{})
  log.SetOutput(os.Stdout)

	if conf.logLevel == "DEBUG" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

func getApiToken() string {
  if token.AccessToken != "" && int(time.Since(token.CreatedAt).Seconds()) < (token.Expires - 600) {
    return token.AccessToken
  }

  log.Debug("Requesting new API token")

  data := url.Values{}
  data.Set("grant_type", "password")
  data.Set("username", conf.username)
  data.Set("password", conf.password)

  r, _ := http.NewRequest("POST", conf.mobicontrolHost + conf.apiBase + "/token", strings.NewReader(data.Encode()))
  r.Header.Add("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(conf.clientId + ":" + conf.clientSecret)))
  r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
  r.Header.Set("User-Agent", httpUserAgent)

  resp, _ := client.Do(r)

  defer resp.Body.Close()

  body, _ := ioutil.ReadAll(resp.Body)

	jsonErr := json.Unmarshal(body, &token)
  token.CreatedAt = time.Now()

	if jsonErr != nil {
		log.Fatal(fmt.Sprintf("Error getting token: %d", jsonErr))
	}

	log.Debug(fmt.Sprintf("Received new API token that expires in %d seconds", token.Expires))

  return token.AccessToken
}

func getMobiData(apiPath string) []byte {
  r, _ := http.NewRequest("GET", conf.mobicontrolHost + conf.apiBase + apiPath, nil)
  r.Header.Add("Authorization", "Bearer " + getApiToken())
  r.Header.Set("User-Agent", httpUserAgent)
  start := time.Now()
  resp, _ := client.Do(r)
  apiLatency.WithLabelValues(apiPath).Set(time.Since(start).Seconds())

  defer resp.Body.Close()

  body, readErr := ioutil.ReadAll(resp.Body)

	if readErr != nil {
		log.Fatal(fmt.Sprintf("Error reading data for apiPath %d: %d", apiPath, readErr))
	}

  return body
}

func GetServers() mobiControlServerStatus {
	servers := mobiControlServerStatus{}

	results := getMobiData("/servers")

  err := json.Unmarshal(results, &servers)

  if err != nil {
		log.Fatal(fmt.Sprintf("Error parsing server data: %d", err))
  }

	return servers
}

func GetDevices() []mobiControlDevice {
	devices := []mobiControlDevice{}

	results := getMobiData("/devices")

  err := json.Unmarshal(results, &devices)

  if err != nil {
    log.Fatal(fmt.Sprintf("Error parsing device data: %d", err))
  }

	return devices
}
