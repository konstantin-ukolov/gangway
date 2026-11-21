package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	server := flag.String("server", "", "Gangway HTTPS URL")
	username := flag.String("username", "", "Expected OIDC username")
	interactive := flag.Bool("login", false, "Interactively exchange a one-time code and save credentials")
	cachePath := flag.String("cache", defaultCachePath(), "Credential cache path")
	flag.Parse()
	if !*interactive {
		return emitCachedCredential(*cachePath)
	}
	u, err := url.Parse(*server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("--server must be an HTTPS URL")
	}
	if *username == "" {
		return fmt.Errorf("--username is required")
	}
	fmt.Fprintf(os.Stderr, "Open %s/commandline in your browser. Select the login utility tab and generate a one-time code for %s.\nPaste code (valid for 2 minutes): ", strings.TrimRight(*server, "/"), *username)
	code, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(strings.TrimRight(*server, "/")+"/redeem", url.Values{"code": {strings.TrimSpace(code)}, "username": {*username}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("login failed (HTTP %d); generate a new code", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}
	var credential struct {
		Kind       string
		APIVersion string
		Status     struct{ Token string }
	}
	if json.Unmarshal(data, &credential) != nil || credential.Kind != "ExecCredential" || credential.APIVersion != "client.authentication.k8s.io/v1" || credential.Status.Token == "" {
		return fmt.Errorf("invalid credential response")
	}
	if err := saveCredential(*cachePath, data); err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func defaultCachePath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "gangway-login", "credential.json")
	}
	return filepath.Join(os.TempDir(), "gangway-login-credential.json")
}

func saveCredential(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create credential directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("cannot save credential cache: %w", err)
	}
	return nil
}

func emitCachedCredential(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no cached login found; run gangway-login --login --server <gangway-url> --username <username>")
	}
	var credential struct {
		Kind       string
		APIVersion string
		Status     struct {
			Token               string
			ExpirationTimestamp string
		}
	}
	if err := json.Unmarshal(data, &credential); err != nil || credential.Kind != "ExecCredential" || credential.APIVersion != "client.authentication.k8s.io/v1" || credential.Status.Token == "" {
		return fmt.Errorf("invalid credential cache; run gangway-login --login to authenticate again")
	}
	if credential.Status.ExpirationTimestamp != "" {
		expires, err := time.Parse(time.RFC3339, credential.Status.ExpirationTimestamp)
		if err == nil && !expires.After(time.Now()) {
			return fmt.Errorf("cached token expired; run gangway-login --login to authenticate again")
		}
	}
	_, err = os.Stdout.Write(data)
	return err
}
