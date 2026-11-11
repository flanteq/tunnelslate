package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"tunnelslate/internal/buildinfo"
)

func TestVersionIsPublicAndMatchesAuthenticatedDashboard(t *testing.T) {
	h, db, cfg := fixture(t)
	for _, prefix := range []string{"", "/ovpn"} {
		t.Run(prefix, func(t *testing.T) {
			cfg.BasePath = prefix
			s, err := New(cfg, db)
			if err != nil {
				t.Fatal(err)
			}
			check := func(path string, cookie *http.Cookie) {
				t.Helper()
				w := request(s, "GET", prefix+path, "", cookie, "", "")
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || body["version"] != buildinfo.Version || body["version"] == "" {
					t.Fatal("incorrect build version", path, w.Code, body, err)
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("version response can be cached")
				}
				if path == "/api/version" && len(body) != 1 {
					t.Fatal("public endpoint exposed unrelated information", body)
				}
			}
			check("/api/version", nil)
			if w := request(s, "GET", prefix+"/api/dashboard", "", nil, "", ""); w.Code != 401 {
				t.Fatal("dashboard became public")
			}
			cookie, _ := signIn(t, h)
			check("/api/dashboard", cookie)
			if prefix != "" {
				if w := request(s, "GET", "/api/version", "", nil, "", ""); w.Code != 404 {
					t.Fatal("version endpoint leaked outside base path", w.Code)
				}
			}
		})
	}
}
