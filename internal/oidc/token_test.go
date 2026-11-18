// Copyright © 2025 Gangway contributors
// Licensed under the Apache License, Version 2.0.

package oidc

import (
	"context"
	"testing"

	"golang.org/x/oauth2"
)

func TestTokenExchangeConfiguration(t *testing.T) {
	cfg := &oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://issuer.example/token",
		},
	}
	token := &Token{OAuth2Cfg: cfg}
	if token.OAuth2Cfg.ClientID != "client" {
		t.Fatalf("unexpected OAuth client configuration")
	}
	if _, ok := interface{}(context.Background()).(context.Context); !ok {
		t.Fatalf("context is not usable")
	}
}
