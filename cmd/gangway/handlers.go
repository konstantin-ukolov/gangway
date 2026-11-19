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
	"time"

	"github.com/heptiolabs/gangway/internal/session"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/yaml"
)

const (
	templatesBase       = "/templates"
	serverSessionCookie = "gangway_session"
)

func (a *App) setServerSessionCookie(w http.ResponseWriter, id string) {
	maxAge := 8 * time.Hour
	if a != nil && a.Config != nil && a.Config.SessionTTLHours > 0 {
		maxAge = time.Duration(a.Config.SessionTTLHours) * time.Hour
	}
	http.SetCookie(w, &http.Cookie{Name: serverSessionCookie, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge.Seconds())})
}

func clearServerSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: serverSessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *App) serverSession(r *http.Request) (string, session.ServerSession, bool) {
	if a.Sessions == nil {
		return "", session.ServerSession{}, false
	}
	cookie, err := r.Cookie(serverSessionCookie)
	if err != nil {
		return "", session.ServerSession{}, false
	}
	value, ok := a.Sessions.Get(cookie.Value)
	return cookie.Value, value, ok
}

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
	RedirectURL  string
	LogoutCSRF   string
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// homeInfo is used to store dynamic properties on
type homeInfo struct {
	HTTPPath    string
	AppName     string
	ClusterName string
	CompanyName string
	CompanyLogo string
}

func (a *App) serveTemplate(tmplFile string, data interface{}, w http.ResponseWriter) {
	var (
		templatePath string
		templateData []byte
		err          error
	)

	// Use custom templates if provided
	if a.Config.CustomHTMLTemplatesDir != "" {
		templatePath = filepath.Join(a.Config.CustomHTMLTemplatesDir, tmplFile)
		templateData, err = ioutil.ReadFile(templatePath)
	} else {
		templatePath = filepath.Join(templatesBase, tmplFile)
		templateData, err = templateFS.ReadFile(filepath.Join("templates", tmplFile))
	}

	if err != nil {
		log.Errorf("Failed to find template asset: %s at path: %s", tmplFile, templatePath)
		http.Error(w, "Unable to render page", http.StatusInternalServerError)
		return
	}

	tmpl := htmltemplate.New(tmplFile).Funcs(htmltemplate.FuncMap{"trimSuffix": strings.TrimSuffix})
	tmpl, err = tmpl.Parse(string(templateData))
	if err != nil {
		log.Errorf("Failed to parse template: %v", err)
		http.Error(w, "Unable to render page", http.StatusInternalServerError)
		return
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

func (a *App) loginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, current, ok := a.serverSession(r)
		if !ok || current.IDToken == "" {
			http.Redirect(w, r, a.Config.GetRootPathPrefix(), http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) homeHandler(w http.ResponseWriter, r *http.Request) {
	data := &homeInfo{
		HTTPPath:    a.Config.HTTPPath,
		AppName:     a.Config.AppName,
		ClusterName: a.Config.ClusterName,
		CompanyName: a.Config.CompanyName,
		CompanyLogo: a.Config.CompanyLogo,
	}

	a.serveTemplate("home.tmpl", data, w)
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "Could not generate OAuth state", http.StatusInternalServerError)
		return
	}
	state := url.QueryEscape(base64.StdEncoding.EncodeToString(b))
	logoutCSRF, err := randomToken()
	if err != nil {
		http.Error(w, "Could not generate session token", http.StatusInternalServerError)
		return
	}
	id, err := a.Sessions.Create()
	if err != nil {
		http.Error(w, "Could not create session", http.StatusInternalServerError)
		return
	}
	if err := a.Sessions.Save(id, session.ServerSession{State: state, StateExpiresAt: time.Now().Add(time.Duration(a.Config.OAuthStateTTLMinutes) * time.Minute), LogoutCSRF: logoutCSRF}); err != nil {
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}
	a.setServerSessionCookie(w, id)
	audience := oauth2.SetAuthURLParam("audience", a.Config.Audience)
	http.Redirect(w, r, a.OAuth2Config.AuthCodeURL(state, audience), http.StatusTemporaryRedirect)
}

func (a *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, current, ok := a.serverSession(r)
	if !ok || current.LogoutCSRF == "" || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(current.LogoutCSRF)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	a.Sessions.Delete(id)
	clearServerSessionCookie(w)
	http.Redirect(w, r, a.Config.GetRootPathPrefix(), http.StatusTemporaryRedirect)
}

func (a *App) callbackHandler(w http.ResponseWriter, r *http.Request) {
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
	{
		id, current, ok := a.serverSession(r)
		if !ok || current.State == "" || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(current.State)) != 1 {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		current.State = ""
		if err := a.Sessions.Save(id, current); err != nil {
			http.Error(w, "Could not save OAuth session", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.Transport.HTTPClient)
		token, err := a.Token.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Could not exchange authorization code", http.StatusInternalServerError)
			return
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok || idToken == "" {
			http.Error(w, "OIDC provider did not return an ID token", http.StatusUnauthorized)
			return
		}
		current.IDToken = idToken
		current.RefreshToken = token.RefreshToken
		if err := a.Sessions.Save(id, current); err != nil {
			http.Error(w, "Could not save OAuth session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%s/commandline", a.Config.HTTPPath), http.StatusSeeOther)
		return
	}
}

func (a *App) commandlineHandler(w http.ResponseWriter, r *http.Request) {
	info := a.generateInfo(w, r)
	if info == nil {
		// generateInfo writes to the ResponseWriter if it encounters an error.
		// TODO(abrand): Refactor this.
		return
	}

	a.serveTemplate("commandline.tmpl", info, w)
}

func (a *App) kubeConfigHandler(w http.ResponseWriter, r *http.Request) {
	info := a.generateInfo(w, r)
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
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Write(d)
}

func (a *App) generateInfo(w http.ResponseWriter, r *http.Request) *userInfo {
	// read in public ca.crt to output in commandline copy/paste commands
	file, err := os.Open(a.Config.ClusterCAPath)
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

	_, current, ok := a.serverSession(r)
	if !ok || current.IDToken == "" || current.RefreshToken == "" {
		clearServerSessionCookie(w)
		http.Redirect(w, r, a.Config.GetRootPathPrefix(), http.StatusTemporaryRedirect)
		return nil
	}
	return a.generateInfoFromTokens(w, r, current.IDToken, current.RefreshToken, caBytes)
}

func (a *App) generateInfoFromTokens(w http.ResponseWriter, r *http.Request, idToken, refreshToken string, caBytes []byte) *userInfo {
	if a.VerifyIDToken == nil {
		http.Error(w, "OIDC verifier is not initialized", http.StatusInternalServerError)
		return nil
	}
	claims, err := a.VerifyIDToken(r.Context(), idToken)
	if err != nil {
		log.Warnf("OIDC token verification failed: %v", err)
		http.Error(w, "Could not verify OIDC token", http.StatusUnauthorized)
		return nil
	}
	username, ok := claims[a.Config.UsernameClaim].(string)
	if !ok {
		http.Error(w, "Could not parse Username claim", http.StatusInternalServerError)
		return nil
	}
	_, current, _ := a.serverSession(r)
	visibleClaims := make(map[string]interface{})
	for _, name := range []string{"iss", "aud", "sub", "email", "email_verified", "name", "groups", "iat", "exp", "auth_time", "jti", "at_hash", "c_hash"} {
		if value, exists := claims[name]; exists {
			visibleClaims[name] = value
		}
	}
	return &userInfo{ClusterName: a.Config.ClusterName, AppName: a.Config.AppName, CompanyName: a.Config.CompanyName, CompanyLogo: a.Config.CompanyLogo, Username: username, Claims: visibleClaims, KubeCfgUser: strings.Join([]string{username, a.Config.ClusterName}, "@"), IDToken: idToken, RefreshToken: refreshToken, ClientID: a.Config.ClientID, ClientSecret: a.Config.ClientSecret, IssuerURL: a.Config.IssuerURL, APIServerURL: a.Config.APIServerURL, ClusterCA: string(caBytes), HTTPPath: a.Config.HTTPPath, RedirectURL: a.Config.RedirectURL, LogoutCSRF: current.LogoutCSRF}
}
