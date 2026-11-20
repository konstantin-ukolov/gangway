package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type loginCode struct {
	Token, Username string
	Expires         time.Time
}
type codeStore struct {
	sync.Mutex
	codes map[string]loginCode
}

func (a *App) loginCodeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	_, s, ok := a.serverSession(r)
	if !ok || s.LogoutCSRF == "" || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(s.LogoutCSRF)) != 1 {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	info := a.generateInfo(w, r)
	if info == nil {
		return
	}
	code, err := randomToken()
	if err != nil {
		http.Error(w, "cannot create code", 500)
		return
	}
	a.Codes.Lock()
	if a.Codes.codes == nil {
		a.Codes.codes = make(map[string]loginCode)
	}
	for key, v := range a.Codes.codes {
		if time.Now().After(v.Expires) {
			delete(a.Codes.codes, key)
		}
	}
	if len(a.Codes.codes) >= 10000 {
		a.Codes.Unlock()
		http.Error(w, "too many pending codes", 429)
		return
	}
	a.Codes.codes[code] = loginCode{Token: s.IDToken, Username: info.Username, Expires: time.Now().Add(2 * time.Minute)}
	a.Codes.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(code))
}

func (a *App) redeemHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	a.Codes.Lock()
	v, ok := a.Codes.codes[r.Form.Get("code")]
	if ok {
		delete(a.Codes.codes, r.Form.Get("code"))
	}
	a.Codes.Unlock()
	if !ok || time.Now().After(v.Expires) || v.Username != r.Form.Get("username") {
		http.Error(w, "invalid or expired code", 403)
		return
	}
	if a.VerifyIDToken == nil {
		http.Error(w, "OIDC verifier is not initialized", http.StatusInternalServerError)
		return
	}
	claims, err := a.VerifyIDToken(r.Context(), v.Token)
	if err != nil {
		http.Error(w, "invalid token", 401)
		return
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= float64(time.Now().Unix()) {
		http.Error(w, "expired token", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "status": map[string]interface{}{"token": v.Token, "expirationTimestamp": time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)}})
}

func (a *App) helperHandler(w http.ResponseWriter, r *http.Request) {
	platform := r.URL.Query().Get("platform")
	name, ok := helperFilename(platform)
	if !ok {
		http.NotFound(w, r)
		return
	}
	downloadName := "gangway-login"
	if strings.HasSuffix(name, ".exe") {
		downloadName += ".exe"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+downloadName+`"`)
	http.ServeFile(w, r, filepath.Join("/opt/gangway/helpers", name))
}

func (a *App) publicURL() string {
	u, _ := url.Parse(a.Config.RedirectURL)
	u.Path = a.Config.HTTPPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func helperFilename(platform string) (string, bool) {
	valid := map[string]bool{"linux-amd64": true, "linux-arm64": true, "darwin-amd64": true, "darwin-arm64": true, "windows-amd64": true, "windows-arm64": true}
	if !valid[platform] || strings.Contains(platform, "..") {
		return "", false
	}
	name := "gangway-login-" + platform
	if strings.HasPrefix(platform, "windows-") {
		name += ".exe"
	}
	return name, true
}
