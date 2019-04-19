Istio-Attestor
==

Overview
--

The Istio-Attestor is a plugin for the [SPIRE](https://github.com/spiffe/spire) server. This plugin allows SPIRE to automatically attest nodes from Istio using [K8s Token Review](https://docs.okd.io/latest/rest_api/apis-authentication.k8s.io/v1.TokenReview.html) API to verify bearer tokens from Istio.
In case SPIRE server is running out of kubernetes a kubernetes configuration file is required to do connection to token review api.

Create kubernetes config
--
A script is provided to simplify the proccess of creation of a configuration file, this script will create a new service account
in case it does not exist, if service account with the same name exist it will use it to generate it.
It is only necessary if it is running outside kubernetes.

To run this script run 

```bash
./createKubeConfig.sh <serviceAccount> <namespace>
```
for example: 
```bash
./createKubeConfig.sh spire default
```

output: 
```bash 
Service account spire exist

Getting secret of service account spire on default

Extracting ca.crt from secret...
Getting user token from secret...
Setting current context to: minikube
Cluster name: minikube
Endpoint: https://192.168.99.251:8443

Preparing k8s-spire-default-conf
Setting a cluster entry in kubeconfig...Cluster "minikube" set.
Setting token credentials entry in kubeconfig...User "spire-default-minikube" set.
Setting a context entry in kubeconfig...Context "spire-default-minikube" modified.
Setting the current-context in the kubeconfig file...Switched to context "spire-default-minikube".

Configuration file 'k8s-spire-default-conf' done!!!!
```

As result a configuration file is created with name `k8s-<serviceAccount>-<namespace>-conf`

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: <SERVICE ACCOUNT CA.CRT>
    server: https://192.168.99.251:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    namespace: default
    user: spire-default-minikube
  name: spire-default-minikube
current-context: spire-default-minikube
kind: Config
preferences: {}
users:
- name: spire-default-minikube
  user:
    as-user-extra: {}
    token: <SERVICE ACCOUNT TOKEN>
```

Configuration file can be tested running a kubectl:
```bash
KUBECONFIG=<CONFIG_FILE> kubectl get pods
```
output
```bash
NAME                     READY     STATUS    RESTARTS   AGE
sleep-84488db7b7-ghrmw   2/2       Running   0          10h
```

Usage
--

The plugin can be installed directly by running: 

```bash
go install github.com/spiffe/istio-attestor
```

It will download, build, and install the Istio-Attestor plugin in your `${GOPATH}/bin` directory by default, or in the path set by the `${GOBIN}` environment variable.


**Build from Source**

1. Clone this repo:

  ```bash
  git clone https://github.com/spiffe/istio-attestor ${GOPATH}/src/github.com/spiffe/istio-attestor
  cd ${GOPATH}/src/github.com/spiffe/istio-attestor
  ```

2. Build the Istio-Attestor:

  ```bash
  make build
  ```

Installation and Configuration
--
1. Edit the SPIRE Server config file to add the Istio-Attestor server plugin config:
```bash
edit <SPIRE Installation Directory/conf/server/server.conf>
```

2. Disable agent id validation:
```
server {
   ...
  experimental {
       allow_agentless_node_attestors = true
   }
   ...
}
```

3. Add plugin configuration in "plugin" section:
```
plugins {
   ...
   NodeAttestor "istio_attestor" {
       plugin_cmd = "<PATH TO PLUGIN>"
       plugin_data {
           # Path to kubernetes config, in case it is not provided 
           # attestor is configured as it is inside k8s
           k8s_config_path = "/etc/k8s-spire-default-conf"
       }
   }
   ...
}
```

Start SPIRE with Istio-Attestor plugins
--

**SPIRE Server**

```bash
cd <SPIRE Installation Directory>
./spire-server run
```
