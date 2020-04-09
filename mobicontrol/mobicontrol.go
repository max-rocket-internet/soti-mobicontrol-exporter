package mobicontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math"
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

type mobiControlDeviceResults struct {
	Error   error
	Devices []mobiControlDevice
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
	skip  int
	take  int
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

func getApiToken() (string, error) {
	if token.AccessToken != "" && int(time.Since(token.CreatedAt).Seconds()) < (token.Expires-600) {
		return token.AccessToken, nil
	}

	log.Debug("Requesting new API token")

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", conf.username)
	data.Set("password", conf.password)

	req, err := retryablehttp.NewRequest("POST", conf.mobicontrolHost+conf.apiBase+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		log.Error(fmt.Sprintf("Error creating token request: %v", err))
		return "", err
	}

	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(conf.clientId+":"+conf.clientSecret)))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Set("User-Agent", httpUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		log.Error(fmt.Sprintf("Error in token response: %v", err))
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(fmt.Sprintf("Error reading token response body: %v", err))
		return "", err
	}

	err = json.Unmarshal(body, &token)
	if err != nil {
		log.Error(fmt.Sprintf("Error unmarshalling token data: %v", err))
		return "", err
	}

	token.CreatedAt = time.Now()

	log.Debug(fmt.Sprintf("Received new API token that expires in %v seconds", token.Expires))

	return token.AccessToken, nil
}

func getData(apiPath string, token string) ([]byte, error) {
	req, err := retryablehttp.NewRequest("GET", conf.mobicontrolHost+conf.apiBase+apiPath, nil)
	req.Header.Add("Authorization", "Bearer "+token)
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
	totalDevices := 0
	apiPath := "/devices/summary"
	deviceCountResponse := []mobiControlDeviceSummaryResponse{}

	token, err := getApiToken()
	if err != nil {
		log.Error(fmt.Sprintf("Error getting token: %v", err))
		return 0
	}

	query := make([]mobiControlDeviceSummaryQuery, 0)
	query = append(query, mobiControlDeviceSummaryQuery{DevicePropertyName: "IsAgentOnline", AggregationName: "ID1_IsAgentOnline"})
	queryMarshalled, _ := json.Marshal(query)
	queryData := []byte(string(queryMarshalled))
	req, err := retryablehttp.NewRequest("POST", conf.mobicontrolHost+conf.apiBase+apiPath, bytes.NewBuffer(queryData))
	if err != nil {
		log.Error(fmt.Sprintf("Error creating device summary request: %v", err))
		return 0
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := client.Do(req)
	apiLatency.WithLabelValues(apiPath).Set(time.Since(start).Seconds())
	if err != nil {
		log.Error(fmt.Sprintf("Error in device summary response: %v", err))
		return 0
	}

	log.Debug(fmt.Sprintf("API response %v: %v", resp.StatusCode, apiPath))

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(fmt.Sprintf("Error reading data for device summary: %v", err))
		return 0
	}

	err = json.Unmarshal(body, &deviceCountResponse)
	if err != nil {
		log.Error(fmt.Sprintf("Error unmarshalling device summary data: %v", err))
		return 0
	}

	for _, i := range deviceCountResponse[0].Buckets {
		totalDevices = totalDevices + i.Count
	}

	return totalDevices
}

func GetServers() mobiControlServerStatus {
	serverStatus := mobiControlServerStatus{}
	token, err := getApiToken()
	if err != nil {
		log.Error(fmt.Sprintf("Error getting token: %v", err))
		return serverStatus
	}

	results, err := getData("/servers", token)
	if err != nil {
		log.Error(fmt.Sprintf("Error getting server data: %v", err))
		return serverStatus
	}

	err = json.Unmarshal(results, &serverStatus)
	if err != nil {
		log.Error(fmt.Sprintf("Error unmarshalling server data: %v", err))
		return serverStatus
	}

	return serverStatus
}

func getDevices(skip int, take int, token string) (devices []mobiControlDevice, err error) {
	results, err := getData(fmt.Sprintf("/devices?skip=%d&take=%d", skip, conf.apiPageSize), token)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(results, &devices)
	if err != nil {
		return nil, err
	}

	return devices, nil
}

func Workers(task func(int)) chan int {
	input := make(chan int)

	for i := 0; i < conf.apiConcurrency; i++ {
		go func() {
			for {
				v, ok := <-input
				if ok {
					task(v)
				} else {
					return
				}
			}
		}()
	}

	return input
}

func worker(id int, jobs <-chan deviceJob, results chan<- mobiControlDeviceResults) {
	for j := range jobs {
		deviceResults := mobiControlDeviceResults{}
		log.Debug(fmt.Sprintf("Worker %v starting, skip %v, take %v", id, j.skip, j.take))
		deviceResults.Devices, deviceResults.Error = getDevices(j.skip, j.take, j.token)
		results <- deviceResults
	}
}

func GetAllDevices() []mobiControlDevice {
	all_devices := []mobiControlDevice{}

	token, err := getApiToken()
	if err != nil {
		log.Error(fmt.Sprintf("Error getting token: %v", err))
		return nil
	}

	deviceCount := getDeviceCount()
	numJobs := int(math.Ceil(float64(deviceCount) / float64(conf.apiPageSize)))
	results := make(chan mobiControlDeviceResults, numJobs)
	jobs := make(chan deviceJob, numJobs)

	log.Debug(fmt.Sprintf("Getting %v devices with %v requests", deviceCount, numJobs))

	for id := 1; id <= conf.apiConcurrency; id++ {
		go worker(id, jobs, results)
	}

	skip := 0
	for i := 1; i <= numJobs; i++ {
		job := deviceJob{skip, conf.apiPageSize, token}
		jobs <- job
		skip = skip + conf.apiPageSize
	}

	close(jobs)

	for i := 1; i <= numJobs; i++ {
		jobResults := <-results
		if jobResults.Error != nil {
			log.Error(fmt.Sprintf("Error getting some devices: %v", jobResults.Error))
			return nil
		} else {
			all_devices = append(all_devices, jobResults.Devices...)
		}
	}

	return all_devices
}
