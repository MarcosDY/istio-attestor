Istio-Attestor
==

Overview
--

The Istio-Attestor is a plugin for the [SPIRE](https://github.com/spiffe/spire) server. This plugin allows SPIRE to automatically attest nodes from Istio using [K8s Token Review](https://docs.okd.io/latest/rest_api/apis-authentication.k8s.io/v1.TokenReview.html) API to verify Bearer token from istio.

Create and get service account tokens
--
In case the plugin is used outside k8s, a service account is required.

**Create service account** 

Create a service account `spire`: 
```bash
kubectl create serviceaccount spire
```
**Verify the associated secret:**
A secret should have been created with service account, it can be verified with:
```
kubectl get serviceaccounts spire -o yaml
```
Expected output:
```
apiVersion: v1
kind: ServiceAccount
metadata:
  # ...
secrets:
- name: spire-token-xxxxx
```
**Get service account token**

Now that service account exists and has a secret we can get a token by using kubectl with a secret name and decoding the result from the base64 format so it can be used by the attestor: 
```bash
kubectl get secret $(kubectl get serviceaccounts spire -o "jsonpath={.secrets..name}") -o "jsonpath={.data..token}" | base64 --decode
```

**Get service account ca**
CA is required to verify an http client, to obtain it using kubectl and decode the result:
```bash
kubectl get secret $(kubectl get serviceaccounts spire -o "jsonpath={.secrets..name}") -o "jsonpath={.data['ca\.crt']}" | base64 --decode 
```

**Get kubernetes api address**
```bash
kubectl config view -o jsonpath={.clusters..server}
```

Usage
--

The plugin can be installed directly by running: 

```bash
go install github.com/spiffe/istio-attestor/server
```

It will download, build, and install the Istio-Attestor plugin in your `${GOPATH}/bin` directory by default, or in the path set by the `${GOBIN}` environment variable.


**Build from Source**

1. Clone this repo:

  ```bash
  git clone https://github.com/spiffe/istio-attestor ${GOPATH}/src/github.com/spiffe/istio-attestor
  cd ${GOPATH}/src/github.com/spiffe/istio-attestor
  ```

2. Install utilities:

  ```bash
  make utils
  ```

3. Build the Istio-Attestor:

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
   experimental_skip_agent_id = true
   ...
}
```

3. Add plugin configuration in "plugin" section:
```
plugins {
   ...
   NodeAttestor "istio_attestor" {
       plugin_cmd = "${GOPATH}/src/github.com/spiffe/istio-attestor/bin/server"
       enabled = true
       plugin_data {
           # Path to service account token
           k8s_token_path = "/etc/token"
           # Path to service account ca
           k8s_ca_path = "/etc/ca.crt"
           # Url to k8s api
           k8s_api_server_url = "https://URL:PORT"
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
