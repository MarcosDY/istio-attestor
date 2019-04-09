package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/istio-attestor/k8s"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	pluginName       = "istio_attestor"
	spiffeIdTemplate = "spiffe://%s/ns/%s/sa/%s"

	defaultJwtPath         = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCaCertPath      = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultk8sAPIServerURL = "https://kubernetes.default.svc"
)

// IstioAttestorPlugin implements attestation for Istio's agent node
type IstioAttestorPlugin struct {
	// Path to service account token
	JwtTokenPath string
	// Path to service account ca certificate
	CaCertPath string
	// Url to K8s server where token review api is running
	K8sApiServerUrl string

	// K8s authenticator to verify provided token
	authenticator k8s.JWTValidator
	mtx           *sync.Mutex
}

// IstioAttestorConfig holds hcl configurations for Istio attestor plugin
type IstioAttestorConfig struct {
	JwtTokenPath    string `hcl:"k8s_token_path"`
	CaCertPath      string `hcl:"k8s_ca_path"`
	K8sApiServerUrl string `hcl:"k8s_api_server_url"`
}

type istioAttestedData struct {
	Token       string `json:"token"`
	TrustDomain string `json:"trustDomain"`
}

// New create a new Istio attestor plugin with default values
func New() *IstioAttestorPlugin {
	return &IstioAttestorPlugin{
		JwtTokenPath:    defaultJwtPath,
		CaCertPath:      defaultCaCertPath,
		K8sApiServerUrl: defaultk8sAPIServerURL,

		mtx: &sync.Mutex{},
	}
}

// Attest implements the server side logic to verify provided token using k8s token service
func (i *IstioAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	var attestedData istioAttestedData

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	// verify request is processed for expected plugin
	if req.AttestationData.Type != pluginName {
		return newError("unexpected attestation data type %q", req.AttestationData.Type)
	}

	// extract attested data from Istio
	if err := json.Unmarshal(req.AttestationData.Data, &attestedData); err != nil {
		return newError("error parsing message from attestation data", err)
	}

	// remove "Bearer " and validate token using using token service with provided service account.
	token := strings.TrimPrefix(attestedData.Token, "Bearer ")
	id, err := i.authenticator.ValidateJwt(token)
	if err != nil {
		return newError("provided token from request is not valid: ", err)
	}

	if len(id) != 2 {
		return newError("failed to parse the JWT. Validation result length is not 2, but %d", len(id))
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: fmt.Sprintf(spiffeIdTemplate, attestedData.TrustDomain, id[0], id[1]),
	})
}

// Configure configures the Istio attestor plugin
func (i *IstioAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}
	config := &IstioAttestorConfig{}

	err := hcl.Decode(&config, req.Configuration)
	if err != nil {
		err := newError("error parsing Istio Attestor configuration: %s", err)
		return resp, err
	}

	i.mtx.Lock()
	defer i.mtx.Unlock()

	if config.CaCertPath != "" {
		i.CaCertPath = config.CaCertPath
	}

	if config.JwtTokenPath != "" {
		i.JwtTokenPath = config.JwtTokenPath
	}

	if config.K8sApiServerUrl != "" {
		i.K8sApiServerUrl = config.K8sApiServerUrl
	}

	i.authenticator, err = i.createAuthenticator()

	if err != nil {
		err := newError("error creating authenticator: %v ", err)
		return resp, err
	}

	return resp, nil
}

// createAuthenticator create a K8s authenticator, it use service account's ca and token configured in plugin
// in case those are not specified it use default values inside k8s
func (i IstioAttestorPlugin) createAuthenticator() (k8s.JWTValidator, error) {
	// Load ca from disk
	caCert, err := ioutil.ReadFile(i.CaCertPath)
	if err != nil {
		return nil, err
	}

	// Load token from disk
	reviewerJWT, err := ioutil.ReadFile(i.JwtTokenPath)
	if err != nil {
		return nil, err
	}

	return k8s.NewAuthenticator(i.K8sApiServerUrl, caCert, string(reviewerJWT[:])), nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (i *IstioAttestorPlugin) GetPluginInfo(ctx context.Context, request *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// newError returns an error with istio message format
func newError(format string, args ...interface{}) error {
	return fmt.Errorf("istio: "+format, args...)
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		Plugins: map[string]plugin.Plugin{
			pluginName: nodeattestor.GRPCPlugin{
				ServerImpl: &nodeattestor.GRPCServer{
					Plugin: New(),
				},
			},
		},
		HandshakeConfig: nodeattestor.Handshake,
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}
