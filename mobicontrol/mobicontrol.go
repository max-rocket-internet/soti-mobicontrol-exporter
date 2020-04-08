package mobicontrol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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
	return &Config{
		clientId:        getEnv("CLIENT_ID"),
		clientSecret:    getEnv("CLIENT_SECRET"),
		username:        getEnv("USERNAME"),
		password:        getEnv("PASSWORD"),
		mobicontrolHost: getEnv("MOBICONTROL_HOST"),
		apiBase:         getEnv("API_PREFIX", "/MobiControl/api"),
		logLevel:        getEnv("LOG_LEVEL", "INFO"),
	}
}

func getEnv(params ...string) string {
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

	client = retryablehttp.NewClient()

	token = mobiControlToken{}

	conf = newConfig()

	log = logrus.New()

	apiPageSize = 5000

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
	client.Backoff = retryablehttp.LinearJitterBackoff
	client.RetryWaitMin = 500 * time.Millisecond
	client.RetryWaitMax = 3000 * time.Millisecond
	client.RetryMax = 4
	client.ErrorHandler = retryablehttp.PassthroughErrorHandler
	client.Logger = nil
	client.HTTPClient.Timeout = 30 * time.Second

	level, err := logrus.ParseLevel(conf.logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.Level = level
	log.Formatter = new(logrus.JSONFormatter)
	log.Out = os.Stdout
}

func getApiToken() string {
	if token.AccessToken != "" && int(time.Since(token.CreatedAt).Seconds()) < (token.Expires-600) {
		return token.AccessToken
	}

	log.Debug("Requesting new API token")

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", conf.username)
	data.Set("password", conf.password)

	req, err := retryablehttp.NewRequest("POST", conf.mobicontrolHost+conf.apiBase+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatal(fmt.Sprintf("Error creating token request: %v", err))
	}

	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(conf.clientId+":"+conf.clientSecret)))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Set("User-Agent", httpUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error in token response: %v", err))
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error reading token response body: %v", err))
	}

	err = json.Unmarshal(body, &token)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error unmarshalling token data: %v", err))
	}

	token.CreatedAt = time.Now()

	log.Debug(fmt.Sprintf("Received new API token that expires in %v seconds", token.Expires))

	return token.AccessToken
}

func getMobiData(apiPath string) ([]byte, error) {
	req, err := retryablehttp.NewRequest("GET", conf.mobicontrolHost+conf.apiBase+apiPath, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+getApiToken())
	req.Header.Set("User-Agent", httpUserAgent)
	start := time.Now()
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	apiLatency.WithLabelValues(apiPath).Set(time.Since(start).Seconds())

	log.Debug(fmt.Sprintf("API response %v: %v", resp.StatusCode, apiPath))

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func GetServers() mobiControlServerStatus {
	servers := mobiControlServerStatus{}

	results, err := getMobiData("/servers")
	if err != nil {
		log.Fatal(fmt.Sprintf("Error getting server data: %v", err))
	}

	err = json.Unmarshal(results, &servers)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error unmarshalling server data: %v", err))
	}

	return servers
}

func GetDevices() []mobiControlDevice {
	all_devices := []mobiControlDevice{}
	skip := 0
	count := apiPageSize

	for count == apiPageSize {
		devices := []mobiControlDevice{}

		r, err := getMobiData(fmt.Sprintf("/devices?skip=%d&take=%d", skip, apiPageSize))
		if err != nil {
			log.Fatal(fmt.Sprintf("Error getting getting device data: %v", err))
		}

		skip = skip + apiPageSize

		err = json.Unmarshal(r, &devices)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error unmarshalling device data: %v", err))
		}

		all_devices = append(all_devices, devices...)

		count = len(devices)

		log.Debug(fmt.Sprintf("Got %v devices", count))
	}

	return all_devices
}
