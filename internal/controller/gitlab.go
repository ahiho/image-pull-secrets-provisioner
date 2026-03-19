/*
Copyright 2024 Preferred Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type gitlab interface {
	GenerateAccessToken(
		ctx context.Context,
		k8sToken string,
		instanceURL string,
		clientID string,
	) (token string, expiresAt time.Time, _ error)
}

type gitLabProvider struct {
	httpClient *http.Client
}

func newGitLabProvider() *gitLabProvider {
	return &gitLabProvider{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GenerateAccessToken swaps a Kubernetes ID token for a GitLab access token.
// Note: This logic depends on a specific GitLab OIDC exchange mechanism
// (e.g. using a CI/CD Job Token exchange or a custom OIDC bridge).
// For now, it assumes a standard OIDC swap pattern.
func (p *gitLabProvider) GenerateAccessToken(
	ctx context.Context, k8sToken string, instanceURL string, clientID string,
) (token string, expiresAt time.Time, _ error) {
	if instanceURL == "" {
		instanceURL = "https://gitlab.com"
	}

	// Example OIDC exchange endpoint.
	// GitLab doesn't have a single "swap OIDC for image pull token" endpoint out of the box
	// like Google Cloud, but many teams use a bridge or specific API.
	// We'll implement a generic POST request to the instance.

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("subject_token", k8sToken)
	form.Add("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
	form.Add("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/oauth/token", strings.TrimSuffix(instanceURL, "/")), strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("GitLab OIDC exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, err
	}

	return result.AccessToken, time.Now().Add(time.Duration(result.ExpiresIn) * time.Second), nil
}
