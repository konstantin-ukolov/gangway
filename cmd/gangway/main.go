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
	"crypto/tls"
	"embed"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/heptiolabs/gangway/internal/config"
	"github.com/heptiolabs/gangway/internal/oidc"
	"github.com/heptiolabs/gangway/internal/session"
	"github.com/justinas/alice"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type App struct {
	Config        *config.Config
	OAuth2Config  *oauth2.Config
	Token         oidc.OAuth2Token
	Sessions      *session.MemoryStore
	Transport     *config.TransportConfig
	OIDCVerifier  *coreosoidc.IDTokenVerifier
	VerifyIDToken func(context.Context, string) (map[string]interface{}, error)
}

//go:embed templates/*
var templateFS embed.FS

// wrapper function for http logging
func httpLogger(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		defer log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		fn(w, r)
	}
}

func main() {
	cfgFile := flag.String("config", "", "The config file to use.")
	flag.Parse()

	var err error
	cfg, err := config.NewConfig(*cfgFile)
	if err != nil {
		log.Errorf("Could not parse config file: %s", err)
		os.Exit(1)
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthorizeURL,
			TokenURL: cfg.TokenURL,
		},
	}

	o2token := &oidc.Token{
		OAuth2Cfg: oauth2Cfg,
	}

	transportConfig := config.NewTransportConfig(cfg.TrustedCAPath)
	providerContext := context.WithValue(context.Background(), oauth2.HTTPClient, transportConfig.HTTPClient)
	provider, err := coreosoidc.NewProvider(providerContext, cfg.IssuerURL)
	if err != nil {
		log.Errorf("Could not initialize OIDC provider: %s", err)
		os.Exit(1)
	}
	oidcVerifier := provider.Verifier(&coreosoidc.Config{ClientID: cfg.ClientID})
	verifyIDToken := func(ctx context.Context, raw string) (map[string]interface{}, error) {
		token, err := oidcVerifier.Verify(ctx, raw)
		if err != nil {
			return nil, err
		}
		claims := make(map[string]interface{})
		if err := token.Claims(&claims); err != nil {
			return nil, err
		}
		return claims, nil
	}
	// OIDC tokens are kept in process memory; the browser receives only an
	// opaque session ID. This deployment intentionally runs one replica.
	serverSessionStore := session.NewMemoryStore(time.Duration(cfg.SessionTTLHours)*time.Hour, cfg.SessionMaxCount)
	app := &App{Config: cfg, OAuth2Config: oauth2Cfg, Token: o2token, Sessions: serverSessionStore, Transport: transportConfig, OIDCVerifier: oidcVerifier, VerifyIDToken: verifyIDToken}
	cleanupStop := make(chan struct{})
	defer close(cleanupStop)
	app.Sessions.StartCleanup(time.Minute, cleanupStop)

	loginRequiredHandlers := alice.New(app.loginRequired)

	http.HandleFunc(cfg.GetRootPathPrefix(), httpLogger(app.homeHandler))
	http.HandleFunc(fmt.Sprintf("%s/login", cfg.HTTPPath), httpLogger(app.loginHandler))
	http.HandleFunc(fmt.Sprintf("%s/callback", cfg.HTTPPath), httpLogger(app.callbackHandler))
	http.HandleFunc(fmt.Sprintf("%s/assets/layered-logo.svg", cfg.HTTPPath), func(w http.ResponseWriter, r *http.Request) {
		logo, err := templateFS.ReadFile("templates/layered-logo.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(logo)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	http.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if app.Sessions == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// middleware'd routes
	http.Handle(fmt.Sprintf("%s/logout", cfg.HTTPPath), loginRequiredHandlers.ThenFunc(app.logoutHandler))
	http.Handle(fmt.Sprintf("%s/commandline", cfg.HTTPPath), loginRequiredHandlers.ThenFunc(app.commandlineHandler))
	http.Handle(fmt.Sprintf("%s/kubeconf", cfg.HTTPPath), loginRequiredHandlers.ThenFunc(app.kubeConfigHandler))

	bindAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	// create http server with timeouts
	httpServer := &http.Server{
		Addr:              bindAddr,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if cfg.ServeTLS {
		// update http server with TLS config
		httpServer.TLSConfig = &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			},
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
		}
	}

	// start up the http server
	serverErr := make(chan error, 1)
	go func() {
		log.Infof("Gangway started! Listening on: %s", bindAddr)

		// exit with FATAL logging why we could not start
		// example: FATA[0000] listen tcp 0.0.0.0:8080: bind: address already in use
		if cfg.ServeTLS {
			serverErr <- httpServer.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
		} else {
			serverErr <- httpServer.ListenAndServe()
		}
	}()

	// create channel listening for signals so we can have graceful shutdowns
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-signalChan:
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("HTTP server failed: %s", err)
		}
		return
	}

	log.Println("Shutdown signal received, exiting.")
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		log.Errorf("HTTP server shutdown failed: %s", err)
	}
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("HTTP server failed during shutdown: %s", err)
		}
	default:
	}
}
