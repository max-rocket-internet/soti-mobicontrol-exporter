# Soti MobiControl Prometheus exporter

<img src="https://raw.githubusercontent.com/max-rocket-internet/soti-mobicontrol-exporter/master/img/prometheus-logo.png" height="75">   <img src="https://raw.githubusercontent.com/max-rocket-internet/soti-mobicontrol-exporter/master/img/mc-logo.svg?sanitize=true" height="75">

A [Prometheus exporter](https://prometheus.io/docs/instrumenting/exporters/) for [SOTI MobiControl](https://soti.net/mobicontrol).

This exporter will expose the following metrics under the namespace `soti_mc` in Prometheus:

- Device agent online status by these labels:
  - Server name
  - Cellular carrier
  - Network connection type
  - Path in full
  - Each device group
- Device cellular signal strength by the same labels are above
- Device events in the last 60 mins by same labels are above:
  - Enrollment
  - Last check in
  - Last_agent connect
  - Last agent disconnect
- REST API latency
- Servers version
- Servers status

Example:

```
# HELP soti_mc_api_latency Latency of SOTI MobiControl API endpoints
# TYPE soti_mc_api_latency gauge
soti_mc_api_latency{endpoint="/devices"} 0.296906808
soti_mc_api_latency{endpoint="/servers"} 0.266505251

# HELP soti_mc_devices_agent_online Agent online status of SOTI MobiControl devices
# TYPE soti_mc_devices_agent_online gauge
soti_mc_devices_agent_online{cellular_carrier="",network_connection_type="Wifi",online="0",path="\\\\My Company Global\\MyDevice - Model xxxx",path_split_1="",path_split_2="",path_split_3="My Company Global",path_split_4="MyDevice - Model xxxx",path_split_5="",path_split_6="",server_name="S99999"} 1
soti_mc_devices_agent_online{cellular_carrier="",network_connection_type="Wifi",online="0",path="\\\\My Company\\USA\\SomeCompany\\NYC",path_split_1="",path_split_2="",path_split_3="My Company",path_split_4="USA",path_split_5="SomeCompany",path_split_6="NYC",server_name="S99999"} 1
soti_mc_devices_agent_online{cellular_carrier="SimService",network_connection_type="Lte",online="0",path="\\\\My Company\\Colombia\\mydomain.com\\Sunmi",path_split_1="",path_split_2="",path_split_3="My Company",path_split_4="Colombia",path_split_5="mydomain.com",path_split_6="Sunmi",server_name="S99999"} 1
soti_mc_devices_agent_online{cellular_carrier="Telekom.de | IoT eSim",network_connection_type="Lte",online="0",path="\\\\My Company\\USA\\SomeCompany\\NYC",path_split_1="",path_split_2="",path_split_3="My Company",path_split_4="USA",path_split_5="SomeCompany",path_split_6="NYC",server_name="S99999"} 1

# HELP soti_mc_servers_status Status of SOTI MobiControl API servers by type
# TYPE soti_mc_servers_status gauge
soti_mc_servers_status{status="Offline",type="management"} 1
soti_mc_servers_status{status="Started",type="deployment"} 1
soti_mc_servers_status{status="Started",type="management"} 1

# HELP soti_mc_servers_version Version of SOTI MobiControl servers
# TYPE soti_mc_servers_version gauge
soti_mc_servers_version{version="14.4.0-4857"} 1
```

## Running

This exporter uses environment variables for configuration:

- `CLIENT_ID`: for authentication to the [SOTI REST API](https://www.soti.net/mc/help/v15.0/en/adminutility/tools/restapi.html)
- `CLIENT_SECRET`: for authentication to the [SOTI REST API](https://www.soti.net/mc/help/v15.0/en/adminutility/tools/restapi.html)
- `USERNAME`: for authentication to the [SOTI REST API](https://www.soti.net/mc/help/v15.0/en/adminutility/tools/restapi.html)
- `PASSWORD`: for authentication to the [SOTI REST API](https://www.soti.net/mc/help/v15.0/en/adminutility/tools/restapi.html)
- `MOBICONTROL_HOST`: The host for your MobiControl instance
- `API_PREFIX`: prefix for accessing the SOTI MobiControl REST API, defaults to `/MobiControl/api`
- `LOG_LEVEL`: log level, defaults to `INFO` but can be set to `DEBUG`

Example:

```shell
go build soti-mobicontrol-exporter.go

export CLIENT_ID="abcdefghijk123456789"
export CLIENT_SECRET="abcd/efghijk129sdfsdfsresd"
export USERNAME="user1"
export PASSWORD="password123456"
export MOBICONTROL_HOST="https://s012345.mobicontrolcloud.com"

./soti-mobicontrol-exporter
{"level":"info","msg":"soti-mobicontrol-exporter starting","time":"2020-03-26T16:42:09+01:00"}
```

## Docker image

Here: https://hub.docker.com/r/maxrocketinternet/soti-mobicontrol-exporter

```
docker pull maxrocketinternet/soti-mobicontrol-exporter
```

## Helm chart

Use the included [Helm](https://helm.sh/) chart to install easily on Kubernetes:

```shell
helm install ./chart --set xxx=""
```
