package k8s

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	k8sauth "k8s.io/api/authentication/v1"
)

const (
	maxIdleConnsPerHost = 100
	tokenReviewPath     = "%s/apis/authentication.k8s.io/v1/tokenreviews"
)

// JWTValidator abstracts jwt validations
type JWTValidator interface {
	// NewAuthenticator validate provided jwt
	ValidateJwt(jwt string) ([]string, error)
}

// Authenticator k8s token review api client
type Authenticator struct {
	apiAddr    string
	apiToken   string
	httpClient *http.Client
}

// NewAuthenticator create a k8s authenticator
func NewAuthenticator(apiAddr string, apiCert []byte, apiToken string) *Authenticator {
	return &Authenticator{
		apiAddr:    apiAddr,
		apiToken:   apiToken,
		httpClient: createClient(apiCert),
	}
}

// createClient create an http client with provided ca
func createClient(apiCert []byte) *http.Client {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(apiCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
		},
	}
}

// tokenReview do a token review to k8s to verify if provided token is valid
func (a *Authenticator) tokenReview(jwt string) (*http.Response, error) {

	// Create the TokenReview Object and marshal it into json
	reviewReq := &k8sauth.TokenReview{
		Spec: k8sauth.TokenReviewSpec{
			Token: jwt,
		},
	}
	reviewJSON, err := json.Marshal(reviewReq)
	if err != nil {
		return nil, err
	}

	// create http POST request to k8s token review api
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf(tokenReviewPath, a.apiAddr), bytes.NewBuffer(reviewJSON))
	if err != nil {
		return nil, err
	}

	// set all required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.apiToken))

	// send HTTP request
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send the HTTP request: %v", err)
	}
	return resp, nil
}

// ValidateJwt validate provided jwt with token review api.
func (a *Authenticator) ValidateJwt(jwt string) ([]string, error) {
	// cal token review api to verify jwt token
	resp, err := a.tokenReview(jwt)
	if err != nil {
		return nil, fmt.Errorf("could not get a token review response: %v", err)
	}

	// parse response into token review
	tokenReview, err := parseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("could not parse token review: %v", err)
	}

	if tokenReview.Status.Error != "" {
		return nil, fmt.Errorf("service account authentication status error: %v", tokenReview.Status.Error)
	}

	if !tokenReview.Status.Authenticated {
		return nil, fmt.Errorf("token is not authenticated")
	}

	// verify if use is in service account group
	inServiceAccountGroup := false
	for _, group := range tokenReview.Status.User.Groups {
		if group == "system:serviceaccounts" {
			inServiceAccountGroup = true
			break
		}
	}
	if !inServiceAccountGroup {
		return nil, fmt.Errorf("the token is not a service account")
	}

	// username format: system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)
	subStrings := strings.Split(tokenReview.Status.User.Username, ":")
	if len(subStrings) != 4 {
		return nil, fmt.Errorf("token review returned an invalid username field")
	}
	namespace := subStrings[2]
	saName := subStrings[3]

	return []string{namespace, saName}, nil
}

// parseResponse parse http response into token review
func parseResponse(resp *http.Response) (*k8sauth.TokenReview, error) {
	if !(resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusCreated ||
		resp.StatusCode == http.StatusAccepted) {
		return nil, fmt.Errorf("invalid review response status code %v", resp.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read from the response body: %v", err)
	}
	defer resp.Body.Close()

	tokenReview := &k8sauth.TokenReview{}
	err = json.Unmarshal(bodyBytes, tokenReview)
	if err != nil {
		return nil, fmt.Errorf("unmarshal response body returns an error: %v", err)
	}

	return tokenReview, nil
}
