package server

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublicErrorCodesCoverStaticErrors(t *testing.T) {
	for _, directory := range []string{".", "../pki", "../ccd", "../vpnsettings"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				var expression ast.Expr
				if call, ok := node.(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok && ((ident.Name == "apiError" && len(call.Args) == 3) || (ident.Name == "problem" && len(call.Args) == 2)) {
						expression = call.Args[len(call.Args)-1]
					}
				}
				if field, ok := node.(*ast.KeyValueExpr); ok {
					if key, ok := field.Key.(*ast.Ident); ok && key.Name == "Message" {
						expression = field.Value
					}
				}
				if literal, ok := expression.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					message, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatal(err)
					}
					if _, ok := apiErrorCodes[message]; !ok {
						t.Errorf("%s: public error has no stable code: %s", entry.Name(), message)
					}
				}
				return true
			})
		}
	}
}

func TestErrorParametersAndLanguageIndependentContract(t *testing.T) {
	for _, tc := range []struct{ message, code, param, value string }{
		{"Current password is incorrect", "auth.current_password_invalid", "", ""},
		{"Постоянный VPN-IP должен быть в диапазоне 10.8.0.128–10.8.0.254", "ccd.static_ip_range", "start", "10.8.0.128"},
		{"Новая подсеть несовместима с постоянным IP устройства «<script>alert(1)</script>». Сначала измените или сбросьте его IP.", "vpn.static_ip_conflict", "device", "<script>alert(1)</script>"},
		{"Incomplete existing PKI: missing or invalid ca.crt. Restore or repair it; automatic reset is disabled.", "pki.incomplete", "file", "ca.crt"},
	} {
		w := httptest.NewRecorder()
		apiError(w, 400, tc.message)
		var result struct {
			Error, Code string
			Params      map[string]any
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Code != tc.code || result.Error != tc.message {
			t.Fatalf("unexpected public error: %+v", result)
		}
		if tc.param != "" && result.Params[tc.param] != tc.value {
			t.Fatal("missing error parameter", result.Params)
		}
	}
	code, params := apiErrorDetails(400, "Срок сертификата не может превышать срок центра сертификации: 01.01.2030 00:00 UTC")
	if code != "certificate.ca_expiry" || params["expires_at"] != int64(1893456000) {
		t.Fatal("expiry was not encoded as an absolute timestamp", code, params)
	}
	h, _, cfg := fixture(t)
	for _, language := range []string{"ru-RU", "en-US"} {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader("{"))
		r.Header.Set("Origin", cfg.PublicURL)
		r.Header.Set("Accept-Language", language)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 400 || body["code"] != "auth.login_invalid" {
			t.Fatal("error contract depended on language", language, w.Code, body, err)
		}
	}
}
