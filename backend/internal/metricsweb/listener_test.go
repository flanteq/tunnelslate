package metricsweb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func ca(t *testing.T) authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	b, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(b)
	return authority{cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))}
}
func leaf(t *testing.T, a authority, client, expired bool) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{"metrics.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if client {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if expired {
		tpl.NotAfter = time.Now().Add(-time.Minute)
	}
	b, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
}
func tlsClient(t *testing.T, root authority, cert, key string) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(root.pem))
	conf := &tls.Config{RootCAs: pool, ServerName: "metrics.example.com", MinVersion: tls.VersionTLS12}
	if cert != "" {
		pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		conf.Certificates = []tls.Certificate{pair}
	}
	tr := &http.Transport{TLSClientConfig: conf}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 2 * time.Second}
}
func check(t *testing.T, c *http.Client, url string, want bool) {
	t.Helper()
	r, e := c.Get(url)
	if e != nil {
		if want {
			t.Fatal(e)
		}
		return
	}
	defer r.Body.Close()
	io.Copy(io.Discard, r.Body)
	if !want || r.StatusCode != 200 {
		t.Fatalf("access=%v status=%d", want, r.StatusCode)
	}
}
func TestMTLSVerificationRotationAndDisable(t *testing.T) {
	serverCA := ca(t)
	clientCA := ca(t)
	otherCA := ca(t)
	cert, key := leaf(t, serverCA, false, false)
	config := Config{Enabled: true, MTLS: true, Source: "pem", Cert: cert, Key: key, CA: clientCA.pem}
	p, err := Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	if p.TLS.ClientAuth != tls.RequireAndVerifyClientCert || !p.TLS.SessionTicketsDisabled {
		t.Fatal("unsafe TLS settings")
	}
	manager := New("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("metrics")) }))
	defer manager.Close()
	if err = manager.Apply(p); err != nil {
		t.Fatal(err)
	}
	url := "https://" + manager.Status().Address + "/metrics"
	validCert, validKey := leaf(t, clientCA, true, false)
	good := tlsClient(t, serverCA, validCert, validKey)
	check(t, good, url, true)
	check(t, tlsClient(t, serverCA, "", ""), url, false)
	wrongCert, wrongKey := leaf(t, otherCA, true, false)
	check(t, tlsClient(t, serverCA, wrongCert, wrongKey), url, false)
	oldCert, oldKey := leaf(t, clientCA, true, true)
	check(t, tlsClient(t, serverCA, oldCert, oldKey), url, false)
	check(t, tlsClient(t, otherCA, validCert, validKey), url, false)
	// Keep-alive connection established above must not survive a CA rotation.
	// A stable address is needed when re-binding :0 for this assertion.
	manager.address = manager.Status().Address
	config.CA = otherCA.pem
	p, err = Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Apply(p); err != nil {
		t.Fatal(err)
	}
	check(t, good, url, false)
	check(t, tlsClient(t, serverCA, wrongCert, wrongKey), url, true)
	config.Enabled = false
	p, err = Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Apply(p); err != nil {
		t.Fatal(err)
	}
	check(t, tlsClient(t, serverCA, wrongCert, wrongKey), url, false)
	if manager.Status().State != "disabled" {
		t.Fatal(manager.Status())
	}
}
func TestTLSValidationAndFiles(t *testing.T) {
	a := ca(t)
	cert, key := leaf(t, a, false, false)
	c := Config{Enabled: true, MTLS: true, Source: "pem", Cert: cert, Key: key, CA: a.pem}
	for _, mutate := range []func(*Config){func(c *Config) { c.Key = "invalid" }, func(c *Config) { c.CA = c.Cert }, func(c *Config) { c.Cert, c.Key = leaf(t, a, false, true) }, func(c *Config) { c.Cert, c.Key = leaf(t, a, true, false) }, func(c *Config) { c.Source = "unknown" }} {
		bad := c
		mutate(&bad)
		if _, err := Prepare(bad); err == nil {
			t.Fatal("invalid TLS accepted")
		}
	}
	dir := t.TempDir()
	c.Source = "files"
	c.Directory = dir
	if _, err := Prepare(c); err == nil {
		t.Fatal("missing files accepted")
	}
	for name, value := range map[string]string{"server.crt": cert, "server.key": key, "client-ca.crt": a.pem} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Prepare(c); err != nil {
		t.Fatal(err)
	}
	c.Enabled = false
	c.Key = ""
	if _, err := Prepare(c); err != nil {
		t.Fatal("cannot disable invalid TLS", err)
	}
}

func TestInvalidRotationDoesNotDowngradeTLS(t *testing.T) {
	a := ca(t)
	cert, key := leaf(t, a, false, false)
	manager := New("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer manager.Close()
	// Startup with invalid material never opens a port.
	manager.Failure("metrics.key_pair", true)
	if manager.Status().State != "error" || manager.server != nil {
		t.Fatal("invalid startup opened socket")
	}
	p, err := Prepare(Config{Enabled: true, MTLS: true, Source: "pem", Cert: cert, Key: key, CA: a.pem})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Apply(p); err != nil {
		t.Fatal(err)
	}
	url := "https://" + manager.Status().Address + "/metrics"
	clientCert, clientKey := leaf(t, a, true, false)
	manager.Failure("metrics.key_pair", true)
	check(t, tlsClient(t, a, clientCert, clientKey), url, true)
	check(t, tlsClient(t, a, "", ""), url, false)
	if err = manager.Apply(p); err != nil {
		t.Fatal(err)
	}
	if manager.Status().State != "running" {
		t.Fatal("did not recover")
	}
	// An inability to load a newly requested TLS configuration closes a prior plain listener.
	plain, _ := Prepare(Config{Enabled: true, Source: "files"})
	if err = manager.Apply(plain); err != nil {
		t.Fatal(err)
	}
	manager.Failure("metrics.files", true)
	if manager.server != nil {
		t.Fatal("HTTP retained after TLS failure")
	}
}

func TestCertificateFieldsCannotContainPrivateKeys(t *testing.T) {
	a := ca(t)
	cert, key := leaf(t, a, false, false)
	for _, enabled := range []bool{false, true} {
		for _, source := range []string{"files", "pem"} {
			for _, field := range []string{"cert", "ca"} {
				c := Config{Enabled: enabled, MTLS: true, Source: source, Cert: cert, Key: key, CA: a.pem}
				if field == "cert" {
					c.Cert += key
				} else {
					c.CA += key
				}
				if _, err := Prepare(c); err == nil || err.Error() != "metrics.certificate_only" {
					t.Fatal("private key accepted in public field", field, enabled, source, err)
				}
			}
		}
	}
}
