// Copyright © 2017 Heptio
// Copyright © 2017 Craig Tracey
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/heptiolabs/gangway/internal/config"
	"github.com/heptiolabs/gangway/internal/session"
	"golang.org/x/oauth2"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api/v1"
)

var testApp *App

func testInit() {
	testConfig := (*config.Config)(nil)
	if testApp != nil {
		testConfig = testApp.Config
	}
	if testConfig == nil {
		testConfig = &config.Config{HTTPPath: "", SessionTTLHours: 8, OAuthStateTTLMinutes: 10, UsernameClaim: "sub"}
	}
	sessions := session.NewMemoryStore(time.Hour)
	transport := config.NewTransportConfig("")
	verify := func(_ context.Context, _ string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"sub": "gangway@heptio.com",
			"iss": "GangwayTest",
		}, nil
	}

	oauthConfig := &oauth2.Config{
		ClientID:     "cfg.ClientID",
		ClientSecret: "qwertyuiopasdfghjklzxcvbnm123456",
		RedirectURL:  "cfg.RedirectURL",
	}

	token := &FakeToken{
		OAuth2Cfg: oauthConfig,
	}
	testApp = &App{
		Config:        testConfig,
		OAuth2Config:  oauthConfig,
		Token:         token,
		Sessions:      sessions,
		Transport:     transport,
		VerifyIDToken: verify,
	}
}

func seedServerSession(t *testing.T, req *http.Request, state, idToken, refreshToken string) {
	t.Helper()
	id, err := testApp.Sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	if err := testApp.Sessions.Save(id, session.ServerSession{State: state, IDToken: idToken, RefreshToken: refreshToken}); err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: serverSessionCookie, Value: id})
}

func TestLogoutRequiresPOSTAndCSRF(t *testing.T) {
	testInit()
	testApp.Config = &config.Config{HTTPPath: "", SessionTTLHours: 8}
	req, err := http.NewRequest(http.MethodGet, "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	testApp.logoutHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status: got %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}

	id, err := testApp.Sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	if err := testApp.Sessions.Save(id, session.ServerSession{IDToken: "id", LogoutCSRF: "expected"}); err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token=wrong"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: serverSessionCookie, Value: id})
	rr = httptest.NewRecorder()
	testApp.logoutHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF status: got %d, want %d", rr.Code, http.StatusForbidden)
	}
	if _, ok := testApp.Sessions.Get(id); !ok {
		t.Fatal("session was deleted after invalid CSRF token")
	}
}

func TestHomeHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	testApp.Config = &config.Config{
		HTTPPath: "",
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(testApp.homeHandler)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestCallbackHandler(t *testing.T) {
	tests := map[string]struct {
		params             map[string]string
		expectedStatusCode int
	}{
		"default": {
			params: map[string]string{
				"state": "Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=",
				"code":  "0cj0VQzNl36e4P2L&state=jdep4ov52FeUuzWLDDtSXaF4b5%2F%2FCUJ52xlE69ehnQ8%3D",
			},
			expectedStatusCode: http.StatusSeeOther,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var req *http.Request
			var rsp *httptest.ResponseRecorder
			var err error

			testApp.Config = &config.Config{
				HTTPPath: "/foo",
			}

			// Init variables
			rsp = NewRecorder()
			testInit()
			req, err = http.NewRequest("GET", "/callback", nil)
			if err != nil {
				t.Fatal(err)
			}

			// Add query params to request
			q := req.URL.Query()
			for k, v := range tc.params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			seedServerSession(t, req, tc.params["state"], "", "")

			handler := http.HandlerFunc(testApp.callbackHandler)

			// Call Handler
			handler.ServeHTTP(rsp, req)

			// Validate!
			if status := rsp.Code; status != tc.expectedStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tc.expectedStatusCode)
			}

		})
	}

}

func TestCallbackRejectsExpiredState(t *testing.T) {
	testInit()
	req, err := http.NewRequest(http.MethodGet, "/callback?state=expired&code=code", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := testApp.Sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	if err := testApp.Sessions.Save(id, session.ServerSession{State: "expired", StateExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: serverSessionCookie, Value: id})
	rr := httptest.NewRecorder()
	testApp.callbackHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expired state status: got %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestCallbackRequiresSessionCookie(t *testing.T) {
	testInit()
	req, err := http.NewRequest(http.MethodGet, "/callback?state=state&code=code", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	testApp.callbackHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing session status: got %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestCallbackRejectsOIDCError(t *testing.T) {
	testInit()
	req, err := http.NewRequest(http.MethodGet, "/callback?error=access_denied", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	testApp.callbackHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC error status: got %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}
func TestCommandLineHandler(t *testing.T) {
	tests := map[string]struct {
		params                     map[string]string
		emailClaim                 string
		usernameClaim              string
		expectedStatusCode         int
		expectedUsernameInTemplate string
	}{
		"default": {
			params: map[string]string{
				"state":         "Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=",
				"id_token":      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJHYW5nd2F5VGVzdCIsImlhdCI6MTU0MDA0NjM0NywiZXhwIjoxODg3MjAxNTQ3LCJhdWQiOiJnYW5nd2F5LmhlcHRpby5jb20iLCJzdWIiOiJnYW5nd2F5QGhlcHRpby5jb20iLCJHaXZlbk5hbWUiOiJHYW5nIiwiU3VybmFtZSI6IldheSIsIkVtYWlsIjoiZ2FuZ3dheUBoZXB0aW8uY29tIiwiR3JvdXBzIjoiZGV2LGFkbWluIn0.zNG4Dnxr76J0p4phfsAUYWunioct0krkMiunMynlQsU",
				"refresh_token": "bar",
				"code":          "0cj0VQzNl36e4P2L&state=jdep4ov52FeUuzWLDDtSXaF4b5%2F%2FCUJ52xlE69ehnQ8%3D",
			},
			expectedStatusCode:         http.StatusOK,
			expectedUsernameInTemplate: "gangway@heptio.com",
			emailClaim:                 "Email",
			usernameClaim:              "sub",
		},
		"incorrect username claim": {
			params: map[string]string{
				"state":         "Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=",
				"id_token":      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJHYW5nd2F5VGVzdCIsImlhdCI6MTU0MDA0NjM0NywiZXhwIjoxODg3MjAxNTQ3LCJhdWQiOiJnYW5nd2F5LmhlcHRpby5jb20iLCJzdWIiOiJnYW5nd2F5QGhlcHRpby5jb20iLCJHaXZlbk5hbWUiOiJHYW5nIiwiU3VybmFtZSI6IldheSIsIkVtYWlsIjoiZ2FuZ3dheUBoZXB0aW8uY29tIiwiR3JvdXBzIjoiZGV2LGFkbWluIn0.zNG4Dnxr76J0p4phfsAUYWunioct0krkMiunMynlQsU",
				"refresh_token": "bar",
				"code":          "0cj0VQzNl36e4P2L&state=jdep4ov52FeUuzWLDDtSXaF4b5%2F%2FCUJ52xlE69ehnQ8%3D",
			},
			expectedStatusCode: http.StatusInternalServerError,
			emailClaim:         "Email",
			usernameClaim:      "meh",
		},
		"no email claim": {
			params: map[string]string{
				"state":         "Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=",
				"id_token":      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJHYW5nd2F5VGVzdCIsImlhdCI6MTU0MDA0NjM0NywiZXhwIjoxODg3MjAxNTQ3LCJhdWQiOiJnYW5nd2F5LmhlcHRpby5jb20iLCJzdWIiOiJnYW5nd2F5QGhlcHRpby5jb20iLCJHaXZlbk5hbWUiOiJHYW5nIiwiU3VybmFtZSI6IldheSIsIkVtYWlsIjoiZ2FuZ3dheUBoZXB0aW8uY29tIiwiR3JvdXBzIjoiZGV2LGFkbWluIn0.zNG4Dnxr76J0p4phfsAUYWunioct0krkMiunMynlQsU",
				"refresh_token": "bar",
				"code":          "0cj0VQzNl36e4P2L&state=jdep4ov52FeUuzWLDDtSXaF4b5%2F%2FCUJ52xlE69ehnQ8%3D",
			},
			expectedStatusCode:         http.StatusOK,
			expectedUsernameInTemplate: "gangway@heptio.com@cluster1",
			usernameClaim:              "sub",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var req *http.Request
			var rsp *httptest.ResponseRecorder
			var err error

			testApp.Config = &config.Config{
				HTTPPath:      "/foo",
				EmailClaim:    tc.emailClaim,
				UsernameClaim: tc.usernameClaim,
				ClusterName:   "cluster1",
				APIServerURL:  "https://kubernetes",
			}

			// Init variables
			rsp = NewRecorder()
			testInit()
			req, err = http.NewRequest("GET", "/callback", nil)
			if err != nil {
				t.Fatal(err)
			}

			// Add query params to request
			q := req.URL.Query()
			for k, v := range tc.params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			seedServerSession(t, req, "", tc.params["id_token"], tc.params["refresh_token"])

			handler := http.HandlerFunc(testApp.commandlineHandler)

			// Call Handler
			handler.ServeHTTP(rsp, req)

			// Validate!
			if status := rsp.Code; status != tc.expectedStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tc.expectedStatusCode)
			}
			// if response code is OK then check that username is correct in resultant template
			if rsp.Code == 200 {
				bodyBytes, _ := ioutil.ReadAll(rsp.Body)
				bodyString := string(bodyBytes)
				re := regexp.MustCompile("--user=(.+)")
				found := re.FindString(bodyString)
				if !strings.Contains(found, tc.expectedUsernameInTemplate) {
					t.Errorf("template should contain --user=%s but found %s", tc.expectedUsernameInTemplate, found)
				}
			}
		})
	}
}

func TestKubeconfigHandler(t *testing.T) {
	tests := map[string]struct {
		cfg                                config.Config
		params                             map[string]string
		usernameClaim                      string
		expectedStatusCode                 int
		expectedAuthInfoName               string
		expectedAuthInfoAuthProviderConfig map[string]string
	}{
		"default": {
			cfg: config.Config{
				UsernameClaim: "sub",
				ClusterName:   "cluster1",
				APIServerURL:  "https://kubernetes",
				ClientID:      "someClientID",
				ClientSecret:  "someClientSecret",
				IssuerURL:     "GangwayTest",
			},
			params: map[string]string{
				"id_token":      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJHYW5nd2F5VGVzdCIsImlhdCI6MTU0MDA0NjM0NywiZXhwIjoxODg3MjAxNTQ3LCJhdWQiOiJnYW5nd2F5LmhlcHRpby5jb20iLCJzdWIiOiJnYW5nd2F5QGhlcHRpby5jb20iLCJHaXZlbk5hbWUiOiJHYW5nIiwiU3VybmFtZSI6IldheSIsIkVtYWlsIjoiZ2FuZ3dheUBoZXB0aW8uY29tIiwiR3JvdXBzIjoiZGV2LGFkbWluIn0.zNG4Dnxr76J0p4phfsAUYWunioct0krkMiunMynlQsU",
				"refresh_token": "bar",
			},
			expectedStatusCode:   http.StatusOK,
			usernameClaim:        "sub",
			expectedAuthInfoName: "gangway@heptio.com@cluster1",
			expectedAuthInfoAuthProviderConfig: map[string]string{
				"client-id":      "someClientID",
				"client-secret":  "someClientSecret",
				"id-token":       "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJHYW5nd2F5VGVzdCIsImlhdCI6MTU0MDA0NjM0NywiZXhwIjoxODg3MjAxNTQ3LCJhdWQiOiJnYW5nd2F5LmhlcHRpby5jb20iLCJzdWIiOiJnYW5nd2F5QGhlcHRpby5jb20iLCJHaXZlbk5hbWUiOiJHYW5nIiwiU3VybmFtZSI6IldheSIsIkVtYWlsIjoiZ2FuZ3dheUBoZXB0aW8uY29tIiwiR3JvdXBzIjoiZGV2LGFkbWluIn0.zNG4Dnxr76J0p4phfsAUYWunioct0krkMiunMynlQsU",
				"refresh-token":  "bar",
				"idp-issuer-url": "GangwayTest",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var req *http.Request
			var rsp *httptest.ResponseRecorder
			var err error

			// Create dummy cluster CA file
			clusterCAData := "dummy cluster CA"
			f, err := ioutil.TempFile("", "gangway-kubeconfig-handler-test")
			if err != nil {
				t.Fatalf("Error creating temp file: %v", err)
			}
			fmt.Fprint(f, clusterCAData)

			// Set config global var
			testApp.Config = &tc.cfg
			testApp.Config.ClusterCAPath = f.Name()

			// Init variables
			rsp = NewRecorder()
			testInit()
			req, err = http.NewRequest("GET", "/kubeconf", nil)
			if err != nil {
				t.Fatal(err)
			}

			// Create request
			// Add query params to request
			q := req.URL.Query()
			for k, v := range tc.params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			seedServerSession(t, req, "", tc.params["id_token"], tc.params["refresh_token"])

			handler := http.HandlerFunc(testApp.kubeConfigHandler)

			// Call Handler
			handler.ServeHTTP(rsp, req)

			// Validate
			if status := rsp.Code; status != tc.expectedStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tc.expectedStatusCode)
			}
			// if response code is OK, validate the kubeconfig
			if rsp.Code == 200 {
				if got := rsp.Header().Get("Cache-Control"); got != "no-store" {
					t.Errorf("expected no-store cache policy, got %q", got)
				}
				if got := rsp.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
					t.Errorf("expected download CSP, got %q", got)
				}
				bodyBytes, err := ioutil.ReadAll(rsp.Body)
				if err != nil {
					t.Fatalf("error reading body: %v", err)
				}
				kubeconfig := &clientcmdapi.Config{}
				if err := yaml.Unmarshal(bodyBytes, kubeconfig); err != nil {
					t.Fatalf("error unmarshaling response: %v", err)
				}

				// Validate cluster
				if len(kubeconfig.Clusters) != 1 {
					t.Fatalf("Found %d clusters in the generated kubeconfig, expected 1", len(kubeconfig.Clusters))
				}
				cluster := kubeconfig.Clusters[0]
				if cluster.Name != testApp.Config.ClusterName {
					t.Errorf("Expected cluster name to be %q, but found %q", testApp.Config.ClusterName, kubeconfig.Clusters[0].Name)
				}
				if cluster.Cluster.Server != testApp.Config.APIServerURL {
					t.Errorf("Expected cluster server to be %q, but found %q", testApp.Config.APIServerURL, cluster.Cluster.Server)
				}
				if string(cluster.Cluster.CertificateAuthorityData) != clusterCAData {
					t.Errorf("Expected cluster CA Data %q, but got %q", clusterCAData, string(cluster.Cluster.CertificateAuthorityData))
				}

				// Validate AuthInfo
				if len(kubeconfig.AuthInfos) != 1 {
					t.Fatalf("Found %d users in the generated kubeconfig, expected 1", len(kubeconfig.AuthInfos))
				}
				authInfo := kubeconfig.AuthInfos[0]
				if authInfo.Name != tc.expectedAuthInfoName {
					t.Errorf("Expected AuthInfo.Name %q, but got %q", tc.expectedAuthInfoName, authInfo.Name)
				}

				if authInfo.AuthInfo.AuthProvider == nil || authInfo.AuthInfo.AuthProvider.Name != "oidc" {
					t.Fatal("expected legacy OIDC auth provider")
				}
				if !reflect.DeepEqual(authInfo.AuthInfo.AuthProvider.Config, tc.expectedAuthInfoAuthProviderConfig) {
					t.Errorf("Expected %v, got %v", tc.expectedAuthInfoAuthProviderConfig, authInfo.AuthInfo.AuthProvider.Config)
				}

				// Validate context
				if len(kubeconfig.Contexts) != 1 {
					t.Fatalf("Found %d contexts in the generated kubeconfig, expected 1", len(kubeconfig.Contexts))
				}
				context := kubeconfig.Contexts[0]
				if context.Name != testApp.Config.ClusterName {
					t.Errorf("Expected context name to be %q, but found %q", testApp.Config.ClusterName, context.Name)
				}
				if context.Context.Cluster != cluster.Name {
					t.Errorf("Cluster name %q in context does not match cluster name %q", context.Context.Cluster, cluster.Name)
				}
				if context.Context.AuthInfo != authInfo.Name {
					t.Errorf("AuthInfo name %q in context does not match user name %q", context.Context.AuthInfo, authInfo.Name)
				}
				if kubeconfig.CurrentContext != context.Name {
					t.Errorf("Current context %q does not match context name %q", kubeconfig.CurrentContext, context.Name)
				}
			}
		})
	}
}

func TestUnauthedCommandlineHandlerRedirect(t *testing.T) {
	testInit()

	req, err := http.NewRequest("GET", "/commandline", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(testApp.commandlineHandler)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusTemporaryRedirect {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestKubeConfigExecModeContainsNoTokens(t *testing.T) {
	testInit()
	testApp.Config = &config.Config{HTTPPath: "", ClusterName: "cluster", APIServerURL: "https://api.example", ClientID: "client", IssuerURL: "https://issuer.example", UsernameClaim: "sub"}
	req := httptest.NewRequest(http.MethodGet, "/kubeconf?mode=exec", nil)
	seedServerSession(t, req, "", "id-token", "refresh-token")
	rr := httptest.NewRecorder()
	testApp.kubeConfigHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusOK)
	}
	var kubeconfig clientcmdapi.Config
	if err := yaml.Unmarshal(rr.Body.Bytes(), &kubeconfig); err != nil {
		t.Fatal(err)
	}
	auth := kubeconfig.AuthInfos[0].AuthInfo
	if auth.Exec == nil || auth.Exec.Command != "gangway-login" {
		t.Fatalf("expected gangway-login exec config, got %#v", auth.Exec)
	}
	if auth.AuthProvider != nil || auth.Token != "" || auth.Username != "" || auth.Password != "" {
		t.Fatalf("exec kubeconfig contains inline credentials: %#v", auth)
	}
}

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder() *httptest.ResponseRecorder {
	return &httptest.ResponseRecorder{
		HeaderMap: make(http.Header),
		Body:      new(bytes.Buffer),
	}
}

type FakeToken struct {
	OAuth2Cfg *oauth2.Config
}

// Exchange takes an oauth2 auth token and exchanges for an id_token
func (f *FakeToken) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return (&oauth2.Token{
		AccessToken:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJHYW5nd2F5VGVzdCIsImlhdCI6MTU0MDA0NjM0NywiZXhwIjoxODg3MjAxNTQ3LCJhdWQiOiJnYW5nd2F5LmhlcHRpby5jb20iLCJzdWIiOiJnYW5nd2F5QGhlcHRpby5jb20iLCJHaXZlbk5hbWUiOiJHYW5nIiwiU3VybmFtZSI6IldheSIsIkVtYWlsIjoiZ2FuZ3dheUBoZXB0aW8uY29tIiwiR3JvdXBzIjoiZGV2LGFkbWluIn0.zNG4Dnxr76J0p4phfsAUYWunioct0krkMiunMynlQsU",
		RefreshToken: "4567",
	}).WithExtra(map[string]interface{}{
		"id_token": "test-id-token",
	}), nil
}
