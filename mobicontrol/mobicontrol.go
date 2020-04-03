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
	"math"
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
	apiConcurrency  int
	apiPageSize     int
}

type deviceJob struct {
	skip int
	take int
	token string
}

func newConfig() *Config {
	return &Config{
		clientId:        getEnvString("CLIENT_ID"),
		clientSecret:    getEnvString("CLIENT_SECRET"),
		username:        getEnvString("USERNAME"),
		password:        getEnvString("PASSWORD"),
		mobicontrolHost: getEnvString("MOBICONTROL_HOST"),
		apiBase:         getEnvString("API_PREFIX", "/MobiControl/api"),
		logLevel:        getEnvString("LOG_LEVEL", "INFO"),
		apiConcurrency:  getEnvInt("API_CONCURRECNY", "50"),
		apiPageSize:     getEnvInt("API_PAGE_SIZE", "2000"),
	}
}

func getEnvString(params ...string) string {
	if value, exists := os.LookupEnv(params[0]); exists {
		return value
	} else if len(params) > 1 {
		return params[1]
	} else {
		log.Fatal(fmt.Sprintf("Environment variable %s must be set", params[0]))
		return ""
	}
}

func getEnvInt(params ...string) int {
	if value, exists := os.LookupEnv(params[0]); exists {
		valInt, _ := strconv.Atoi(value)
		return valInt
	} else if len(params) > 1 {
		valInt, _ := strconv.Atoi(params[1])
		return valInt
	} else {
		log.Fatal(fmt.Sprintf("Environment variable %s must be set", params[0]))
		return 0
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

func getDeviceCount() int {
	token := getApiToken()

	apiPath := "/devices/summary"

	deviceCountResponse := []mobiControlDeviceSummaryResponse{}

	query := make([]mobiControlDeviceSummaryQuery, 0)
	query = append(query, mobiControlDeviceSummaryQuery{DevicePropertyName: "IsAgentOnline", AggregationName: "ID1_IsAgentOnline"})
	queryMarshalled, _ := json.Marshal(query)
	queryData := []byte(string(queryMarshalled))

	r, _ := http.NewRequest("POST", conf.mobicontrolHost + conf.apiBase + apiPath, bytes.NewBuffer(queryData))
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

	jsonErr := json.Unmarshal(body, &deviceCountResponse)
	if jsonErr != nil {
		log.Fatal(fmt.Sprintf("Error parsing device summary: %v", jsonErr))
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

func getDevices(skip int, take int, token string) []mobiControlDevice {
	devices := []mobiControlDevice{}
	r := getMobiData(fmt.Sprintf("/devices?skip=%d&take=%d", skip, conf.apiPageSize), token)
	err := json.Unmarshal(r, &devices)

	if err != nil {
		log.Fatal(fmt.Sprintf("Error parsing device data: %v", err))
	}

	return devices
}

func worker(id int, jobs <-chan deviceJob, results chan<- []mobiControlDevice) {
    for j := range jobs {
				log.Debug(fmt.Sprintf("Worker %v starting, skip %v, take %v", id, j.skip, j.take))
				r := getDevices(j.skip, j.take, j.token)
        results <- r
    }
}

func GetAllDevices() []mobiControlDevice {
	all_devices := []mobiControlDevice{}
	token := getApiToken()
	deviceCount := getDeviceCount()
	numJobs := int(math.Ceil(float64(deviceCount / conf.apiPageSize)))
	const concurrency = 2

	results := make(chan []mobiControlDevice, numJobs)
	jobs := make(chan deviceJob, numJobs)

	for w := 1; w <= concurrency; w++ {
			go worker(w, jobs, results)
	}

	skip := 0
	for j := 1; j <= numJobs; j++ {
		e := deviceJob{}
		e.skip = skip
		e.take = conf.apiPageSize
		e.token = token
		jobs <- e
		skip = skip + conf.apiPageSize
	}

	close(jobs)

	for a := 1; a <= numJobs; a++ {
			r := <-results
			all_devices = append(all_devices, r...)
	}

	return all_devices
}
