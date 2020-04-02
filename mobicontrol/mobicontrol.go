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
	"bytes"
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

type mobiControlDeviceSummaryQuery struct {
	DevicePropertyName string
	AggregationName    string
}

type mobiControlDeviceSummaryResponse struct {
	AggregationName string
	OtherCount      int
	Buckets         []mobiControlDeviceSummaryBucket
}

type mobiControlDeviceSummaryBucket struct {
	Value string
	Count int
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

	apiConcurrency = 2
	apiPageSize = 500

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

func getDeviceCount(token string) int {
	deviceCountResponse := []mobiControlDeviceSummaryResponse{}
	apiPath := "/devices/summary"
	x := make([]mobiControlDeviceSummaryQuery, 0)
	x = append(x, mobiControlDeviceSummaryQuery{DevicePropertyName: "IsAgentOnline", AggregationName: "ID1_IsAgentOnline"})
	b, err := json.Marshal(x)
	var jsonStr = []byte(string(b))
	if err != nil {
		log.Fatal(err)
	}

	r, _ := http.NewRequest("POST", conf.mobicontrolHost + conf.apiBase + apiPath, bytes.NewBuffer(jsonStr))
	r.Header.Add("Authorization", "Bearer " + token)
	r.Header.Set("User-Agent", httpUserAgent)
	r.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, _ := client.Do(r)
	apiLatency.WithLabelValues(apiPath).Set(time.Since(start).Seconds())

	log.Debug(fmt.Sprintf("API response %v: %v", resp.StatusCode, apiPath))

	defer resp.Body.Close()

	body, readErr := ioutil.ReadAll(resp.Body)

	if readErr != nil {
		log.Fatal(fmt.Sprintf("Error reading data for apiPath %v: %v", apiPath, readErr))
	}

	err2 := json.Unmarshal(body, &deviceCountResponse)

	if err2 != nil {
		log.Fatal(fmt.Sprintf("Error parsing device summary: %v", err2))
	}

	totalDevices := 0

	for _, i := range deviceCountResponse[0].Buckets {
		totalDevices = totalDevices + i.Count
	}

	log.Debug(fmt.Sprintf("Devices counted: %v", totalDevices))

	return totalDevices
}

func GetServers() mobiControlServerStatus {
	servers := mobiControlServerStatus{}

	results, err := getMobiData("/servers")
	if err != nil {
		log.Fatal(fmt.Sprintf("Error getting server data: %v", err))
	}
	results := getMobiData("/servers", getApiToken())

	err = json.Unmarshal(results, &servers)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error unmarshalling server data: %v", err))
	}

	return servers
}

func getDevice(skip int, take int, token string) []mobiControlDevice {
	devices := []mobiControlDevice{}
	r := getMobiData(fmt.Sprintf("/devices?skip=%d&take=%d", skip, apiPageSize), token)
	err := json.Unmarshal(r, &devices)

	if err != nil {
		log.Fatal(fmt.Sprintf("Error parsing device data: %v", err))
	}

	return devices
}

func GetDevices() []mobiControlDevice {
	all_devices := []mobiControlDevice{}
	token := getApiToken()

	// deviceCount := getDeviceCount(token)
	deviceCount := 6

	ch := make(chan []mobiControlDevice, deviceCount)

	workers := Workers(func(a int) {
		fmt.Println("a: ", a)
    results := getDevice(2, 20, token)
    ch <- results
  })

	for i := 0; i < deviceCount; i++ {
		workers <- i
	}

	for i := 0; i < deviceCount; i++ {
		x := <-ch
		all_devices = append(all_devices, x...)
	}

	fmt.Println("len:", len(all_devices))

	return all_devices
}
