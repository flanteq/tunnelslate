// vpn-auth is invoked by OpenVPN with verified certificate metadata and a
// temporary credentials file. It never receives passwords in argv or env.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tunnelslate/internal/vpnauthwire"
)

const controlDir = "/run/tunnelslate"
const temporaryDir = "/run/openvpn/auth"

type job struct {
	Receipt string              `json:"receipt"`
	Request vpnauthwire.Request `json:"request"`
	Control string              `json:"control"`
}

func main() {
	syscall.Umask(0077)
	if len(os.Args) == 2 && os.Args[1] == "worker" {
		worker()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "connect" {
		os.Exit(connect())
	}
	os.Exit(start())
}
func start() int {
	if len(os.Args) != 2 {
		return 1
	}
	r := vpnauthwire.Request{CommonName: os.Getenv("common_name"), Serial: os.Getenv("tls_serial_hex_0"), IP: os.Getenv("untrusted_ip")}
	if r.IP == "" {
		r.IP = os.Getenv("untrusted_ip6")
	}
	policy, err := vpnauthwire.ReadPolicy(filepath.Join(controlDir, vpnauthwire.PolicyName))
	if err != nil {
		return 1
	}
	entry, ok := policy.Lookup(r)
	if !ok {
		return 1
	}
	if !entry.External {
		return 0
	}
	credentials, err := readTemporary(os.Args[1])
	if err != nil {
		return 1
	}
	lines := strings.Split(string(credentials), "\n")
	if len(lines) < 2 {
		return 1
	}
	r.Username = strings.TrimSuffix(lines[0], "\r")
	r.Password = strings.TrimSuffix(lines[1], "\r")
	// A device requiring a password must never fall back to certificate only.
	if r.Username == "" || r.Password == "" {
		return 1
	}
	control := os.Getenv("auth_control_file")
	if !validTemporary(control) {
		return 1
	}
	receipt := receiptPath(r.CommonName, r.IP, os.Getenv("untrusted_port"))
	if receipt == "" {
		return 1
	}
	body, err := json.Marshal(job{Request: r, Control: control, Receipt: receipt})
	if err != nil || len(body) > vpnauthwire.MaxRequest {
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		return 1
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return 1
	}
	defer reader.Close()
	defer writer.Close()
	cmd := exec.Command(executable, "worker")
	cmd.Env = []string{}
	cmd.Stdin = reader
	// Do not inherit OpenVPN's capture pipe: it would wait for the worker.
	if err = cmd.Start(); err != nil {
		return 1
	}
	reader.Close()
	if _, err = writer.Write(body); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 1
	}
	writer.Close()
	_ = cmd.Process.Release()
	return 2
}
func worker() {
	var j job
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, vpnauthwire.MaxRequest+1))
	if decoder.Decode(&j) != nil || !validTemporary(j.Control) || !validTemporary(j.Receipt) || !strings.HasPrefix(filepath.Base(j.Receipt), "desk-receipt-") {
		return
	}
	allowed := false
	ctx, cancel := context.WithTimeout(context.Background(), vpnauthwire.AuthSocketTimeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", filepath.Join(controlDir, vpnauthwire.SocketName))
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(vpnauthwire.AuthSocketTimeout))
		if json.NewEncoder(conn).Encode(j.Request) == nil {
			var r vpnauthwire.Response
			if json.NewDecoder(io.LimitReader(conn, 1024)).Decode(&r) == nil {
				allowed = r.Allowed && len(r.Version) == 64
				if allowed {
					allowed = writeReceipt(j.Receipt, r.Version) == nil
				}
			}
		}
		conn.Close()
	}
	value := []byte("0")
	if allowed {
		value = []byte("1")
	}
	// Open the existing control file without following links or recreating a
	// file OpenVPN has already removed after cancellation.
	f, err := os.OpenFile(j.Control, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(value)
}
func validTemporary(path string) bool {
	return filepath.Dir(path) == temporaryDir && filepath.Base(path) != "." && filepath.Base(path) != ".."
}
func readTemporary(path string) ([]byte, error) {
	if !validTemporary(path) {
		return nil, errors.New("invalid credentials path")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, vpnauthwire.MaxRequest+1))
	if err != nil || len(b) > vpnauthwire.MaxRequest || bytes.IndexByte(b, 0) >= 0 {
		return nil, errors.New("invalid credentials")
	}
	return b, nil
}

func receiptPath(cn, ip, port string) string {
	parsed := net.ParseIP(ip)
	n, err := strconv.Atoi(port)
	if parsed == nil || err != nil || n < 1 || n > 65535 {
		return ""
	}
	sum := sha256.Sum256([]byte(cn + "/" + parsed.String() + "/" + port))
	return filepath.Join(temporaryDir, "desk-receipt-"+hex.EncodeToString(sum[:]))
}

type receipt struct {
	Version string `json:"version"`
	Created int64  `json:"created"`
}

func writeReceipt(path, version string) error {
	// Cancelled handshakes and renegotiations may not call client-connect.
	entries, _ := os.ReadDir(temporaryDir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "desk-receipt-") {
			if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > 2*time.Minute {
				_ = os.Remove(filepath.Join(temporaryDir, entry.Name()))
			}
		}
	}
	body, _ := json.Marshal(receipt{version, time.Now().Unix()})
	f, err := os.CreateTemp(temporaryDir, ".desk-receipt-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func connect() int {
	ip := os.Getenv("trusted_ip")
	if ip == "" {
		ip = os.Getenv("trusted_ip6")
	}
	r := vpnauthwire.Request{CommonName: os.Getenv("common_name"), Serial: os.Getenv("tls_serial_hex_0"), IP: ip}
	p, err := vpnauthwire.ReadPolicy(filepath.Join(controlDir, vpnauthwire.PolicyName))
	if err != nil {
		return 1
	}
	entry, ok := p.Lookup(r)
	if !ok {
		return 1
	}
	if !entry.External {
		return 0
	}
	path := receiptPath(r.CommonName, ip, os.Getenv("trusted_port"))
	if path == "" {
		return 1
	}
	defer os.Remove(path)
	body, err := readTemporary(path)
	if err != nil {
		return 1
	}
	var result receipt
	if json.Unmarshal(body, &result) != nil || !receiptMatches(entry, result, time.Now().Unix()) {
		return 1
	}
	return 0
}

func receiptMatches(entry vpnauthwire.Entry, result receipt, now int64) bool {
	return len(entry.Version) == 64 && result.Version == entry.Version && result.Created > 0 && now-result.Created <= 60 && result.Created <= now
}
