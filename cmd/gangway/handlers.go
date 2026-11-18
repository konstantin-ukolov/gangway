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
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	htmltemplate "html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/yaml"
)

const (
	templatesBase = "/templates"
)

// userInfo stores information about an authenticated user
type userInfo struct {
	ClusterName  string
	AppName      string
	CompanyName  string
	CompanyLogo  string
	Username     string
	Claims       map[string]interface{}
	KubeCfgUser  string
	IDToken      string
	RefreshToken string
	ClientID     string
	ClientSecret string
	IssuerURL    string
	APIServerURL string
	ClusterCA    string
	HTTPPath     string
}

// homeInfo is used to store dynamic properties on
type homeInfo struct {
	HTTPPath    string
	AppName     string
	ClusterName string
	CompanyName string
	CompanyLogo string
}

func serveTemplate(tmplFile string, data interface{}, w http.ResponseWriter) {
	var (
		templatePath string
		templateData []byte
		err          error
	)

	// Use custom templates if provided
	if cfg.CustomHTMLTemplatesDir != "" {
		templatePath = filepath.Join(cfg.CustomHTMLTemplatesDir, tmplFile)
		templateData, err = ioutil.ReadFile(templatePath)
	} else {
		templatePath = filepath.Join(templatesBase, tmplFile)
		templateData, err = templateFS.ReadFile(filepath.Join("templates", tmplFile))
	}

	if err != nil {
		log.Errorf("Failed to find template asset: %s at path: %s", tmplFile, templatePath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := htmltemplate.New(tmplFile)
	tmpl, err = tmpl.Parse(string(templateData))
	if err != nil {
		log.Errorf("Failed to parse template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	tmpl.ExecuteTemplate(w, tmplFile, data)
}

func generateKubeConfig(cfg *userInfo) clientcmdapi.Config {
	// fill out kubeconfig structure
	kcfg := clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		CurrentContext: cfg.ClusterName,
		Clusters: []clientcmdapi.NamedCluster{
			{
				Name: cfg.ClusterName,
				Cluster: clientcmdapi.Cluster{
					Server:                   cfg.APIServerURL,
					CertificateAuthorityData: []byte(cfg.ClusterCA),
				},
			},
		},
		Contexts: []clientcmdapi.NamedContext{
			{
				Name: cfg.ClusterName,
				Context: clientcmdapi.Context{
					Cluster:  cfg.ClusterName,
					AuthInfo: cfg.KubeCfgUser,
				},
			},
		},
		AuthInfos: []clientcmdapi.NamedAuthInfo{
			{
				Name: cfg.KubeCfgUser,
				AuthInfo: clientcmdapi.AuthInfo{
					AuthProvider: &clientcmdapi.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"client-id":      cfg.ClientID,
							"client-secret":  cfg.ClientSecret,
							"id-token":       cfg.IDToken,
							"idp-issuer-url": cfg.IssuerURL,
							"refresh-token":  cfg.RefreshToken,
						},
					},
				},
			},
		},
	}
	return kcfg
}

func loginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := gangwayUserSession.Session.Get(r, "gangway_id_token")
		if err != nil {
			http.Redirect(w, r, cfg.GetRootPathPrefix(), http.StatusTemporaryRedirect)
			return
		}

		if session.Values["id_token"] == nil {
			http.Redirect(w, r, cfg.GetRootPathPrefix(), http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	data := &homeInfo{
		HTTPPath:    cfg.HTTPPath,
		AppName:     cfg.AppName,
		ClusterName: cfg.ClusterName,
		CompanyName: cfg.CompanyName,
		CompanyLogo: cfg.CompanyLogo,
	}

	serveTemplate("home.tmpl", data, w)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "Could not generate OAuth state", http.StatusInternalServerError)
		return
	}
	state := url.QueryEscape(base64.StdEncoding.EncodeToString(b))

	session, err := gangwayUserSession.Session.Get(r, "gangway")
	if err != nil {
		log.Errorf("Got an error in login: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audience := oauth2.SetAuthURLParam("audience", cfg.Audience)
	url := oauth2Cfg.AuthCodeURL(state, audience)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	gangwayUserSession.Cleanup(w, r, "gangway")
	gangwayUserSession.Cleanup(w, r, "gangway_id_token")
	gangwayUserSession.Cleanup(w, r, "gangway_refresh_token")
	http.Redirect(w, r, cfg.GetRootPathPrefix(), http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	if oauthError := r.URL.Query().Get("error"); oauthError != "" {
		log.Warnf("OIDC authorization failed: %s", oauthError)
		http.Error(w, "OIDC authorization failed", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, transportConfig.HTTPClient)

	// load up session cookies
	session, err := gangwayUserSession.Session.Get(r, "gangway")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionIDToken, err := gangwayUserSession.Session.Get(r, "gangway_id_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionRefreshToken, err := gangwayUserSession.Session.Get(r, "gangway_refresh_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// verify the state string
	state := r.URL.Query().Get("state")

	expectedState, ok := session.Values["state"].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) != 1 {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	delete(session.Values, "state")
	// Persist state consumption before exchanging the code. This prevents a
	// second callback from replaying the same state while the provider is slow.
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Could not save OAuth session", http.StatusInternalServerError)
		return
	}

	// use the access code to retrieve a token
	token, err := o2token.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		http.Error(w, "OIDC provider did not return an ID token", http.StatusUnauthorized)
		return
	}
	sessionIDToken.Values["id_token"] = idToken
	sessionRefreshToken.Values["refresh_token"] = token.RefreshToken

	// save the session cookies
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = sessionIDToken.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = sessionRefreshToken.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/commandline", cfg.HTTPPath), http.StatusSeeOther)
}

func commandlineHandler(w http.ResponseWriter, r *http.Request) {
	info := generateInfo(w, r)
	if info == nil {
		// generateInfo writes to the ResponseWriter if it encounters an error.
		// TODO(abrand): Refactor this.
		return
	}

	serveTemplate("commandline.tmpl", info, w)
}

func kubeConfigHandler(w http.ResponseWriter, r *http.Request) {
	info := generateInfo(w, r)
	if info == nil {
		// generateInfo writes to the ResponseWriter if it encounters an error.
		// TODO(abrand): Refactor this.
		return
	}

	d, err := yaml.Marshal(generateKubeConfig(info))
	if err != nil {
		log.Errorf("Error creating kubeconfig - %s", err.Error())
		http.Error(w, "Error creating kubeconfig", http.StatusInternalServerError)
		return
	}

	// tell the browser the returned content should be downloaded
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kubeconfig.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(d)
}

func generateInfo(w http.ResponseWriter, r *http.Request) *userInfo {
	// read in public ca.crt to output in commandline copy/paste commands
	file, err := os.Open(cfg.ClusterCAPath)
	if err != nil {
		// let us know that we couldn't open the file. This only cause missing output
		// does not impact actual function of program
		log.Errorf("Failed to open CA file. %s", err)
	}
	var caBytes []byte
	if file != nil {
		defer file.Close()
		caBytes, err = ioutil.ReadAll(file)
		if err != nil {
			log.Warningf("Could not read CA file: %s", err)
		}
	}

	// load the session cookies
	sessionIDToken, err := gangwayUserSession.Session.Get(r, "gangway_id_token")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	sessionRefreshToken, err := gangwayUserSession.Session.Get(r, "gangway_refresh_token")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	idToken, ok := sessionIDToken.Values["id_token"].(string)
	if !ok {
		gangwayUserSession.Cleanup(w, r, "gangway")
		gangwayUserSession.Cleanup(w, r, "gangway_id_token")
		gangwayUserSession.Cleanup(w, r, "gangway_refresh_token")

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return nil
	}

	refreshToken, ok := sessionRefreshToken.Values["refresh_token"].(string)
	if !ok {
		gangwayUserSession.Cleanup(w, r, "gangway")
		gangwayUserSession.Cleanup(w, r, "gangway_id_token")
		gangwayUserSession.Cleanup(w, r, "gangway_refresh_token")

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return nil
	}

	if verifyIDToken == nil {
		http.Error(w, "OIDC verifier is not initialized", http.StatusInternalServerError)
		return nil
	}
	claims, err := verifyIDToken(r.Context(), idToken)
	if err != nil {
		log.Warnf("OIDC token verification failed: %v", err)
		http.Error(w, "Could not verify OIDC token", http.StatusUnauthorized)
		return nil
	}

	username, ok := claims[cfg.UsernameClaim].(string)
	if !ok {
		http.Error(w, "Could not parse Username claim", http.StatusInternalServerError)
		return nil
	}

	kubeCfgUser := strings.Join([]string{username, cfg.ClusterName}, "@")

	if cfg.EmailClaim != "" {
		log.Warn("using the Email Claim config setting is deprecated. Gangway uses `UsernameClaim@ClusterName`. This field will be removed in a future version.")
	}

	info := &userInfo{
		ClusterName:  cfg.ClusterName,
		AppName:      cfg.AppName,
		CompanyName:  cfg.CompanyName,
		CompanyLogo:  cfg.CompanyLogo,
		Username:     username,
		Claims:       claims,
		KubeCfgUser:  kubeCfgUser,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		IssuerURL:    cfg.IssuerURL,
		APIServerURL: cfg.APIServerURL,
		ClusterCA:    string(caBytes),
		HTTPPath:     cfg.HTTPPath,
	}
	return info
}
