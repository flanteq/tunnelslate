package management

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Connection struct {
	CommonName     string `json:"common_name"`
	RealAddress    string `json:"real_address"`
	VirtualAddress string `json:"virtual_address"`
	BytesReceived  int64  `json:"bytes_received"`
	BytesSent      int64  `json:"bytes_sent"`
	ConnectedSince int64  `json:"connected_since"`
}

type Client struct {
	Socket string
	mu     sync.Mutex
}

type StatusSnapshot struct {
	Connections  []Connection
	Version      string
	DCOEnabled   *bool
	DCOSupported *bool
}

func (c *Client) command(ctx context.Context, command string, multiline bool) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Socket == "" {
		return nil, fmt.Errorf("management interface is not configured")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("OpenVPN management is unavailable: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	scan := bufio.NewScanner(conn)
	scan.Buffer(make([]byte, 4096), 1<<20)
	if !scan.Scan() {
		return nil, fmt.Errorf("management greeting: %v", scan.Err())
	}
	if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
		return nil, err
	}
	result := []string{}
	size := 0
	for scan.Scan() {
		line := scan.Text()
		size += len(line)
		if size > 4<<20 {
			return nil, fmt.Errorf("management response too large")
		}
		if strings.HasPrefix(line, ">") {
			continue
		}
		if strings.HasPrefix(line, "ERROR:") {
			return nil, fmt.Errorf("management command rejected: %s", line)
		}
		if line == "END" {
			return result, nil
		}
		result = append(result, line)
		if !multiline && strings.HasPrefix(line, "SUCCESS:") {
			return result, nil
		}
	}
	return nil, fmt.Errorf("incomplete management response: %v", scan.Err())
}

func (c *Client) Status(ctx context.Context) ([]Connection, error) {
	status, err := c.ReadStatus(ctx)
	return status.Connections, err
}

// ReadStatus includes the daemon version from the same sample as its clients.
func (c *Client) ReadStatus(ctx context.Context) (StatusSnapshot, error) {
	lines, err := c.command(ctx, "status 3", true)
	if err != nil {
		return StatusSnapshot{}, err
	}
	connections, err := ParseStatus(lines)
	if err != nil {
		return StatusSnapshot{}, err
	}
	result := StatusSnapshot{Connections: connections, Version: statusVersion(lines), DCOEnabled: statusDCO(lines)}
	for _, line := range lines {
		if strings.HasPrefix(line, "TITLE\tOpenVPN ") && result.Version != "" {
			built := strings.Contains(line, "[DCO]")
			result.DCOSupported = &built
			break
		}
	}
	return result, nil
}

// The build's [DCO] flag only indicates support. GLOBAL_STATS reports actual use.
// Older servers and malformed/duplicate values remain unknown, not false.
func statusDCO(lines []string) *bool {
	var result *bool
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || fields[0] != "GLOBAL_STATS" || fields[1] != "dco_enabled" {
			continue
		}
		if result != nil || len(fields) != 3 || (fields[2] != "0" && fields[2] != "1") {
			return nil
		}
		enabled := fields[2] == "1"
		result = &enabled
	}
	return result
}

var versionTitle = regexp.MustCompile(`^OpenVPN ([0-9]+\.[0-9]+(?:\.[0-9]+)?[A-Za-z0-9_.+-]*)(?:[ \t]|$)`)

func statusVersion(lines []string) string {
	for _, line := range lines {
		if title, ok := strings.CutPrefix(line, "TITLE\t"); ok {
			if match := versionTitle.FindStringSubmatch(strings.TrimSpace(title)); match != nil {
				return match[1]
			}
		}
	}
	return ""
}

func ParseStatus(lines []string) ([]Connection, error) {
	result := []Connection{}
	headers := map[string]int{}
	valid := false
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) > 0 && fields[0] == "TITLE" {
			valid = true
		}
		if len(fields) > 2 && fields[0] == "HEADER" && fields[1] == "CLIENT_LIST" {
			for i, name := range fields[2:] {
				headers[name] = i + 1
			}
		}
		if len(fields) == 0 || fields[0] != "CLIENT_LIST" {
			continue
		}
		get := func(name string) string {
			if i, ok := headers[name]; ok && i < len(fields) {
				return fields[i]
			}
			return ""
		}
		number := func(name string) (int64, error) { return strconv.ParseInt(get(name), 10, 64) }
		received, err := number("Bytes Received")
		if err != nil {
			return nil, fmt.Errorf("invalid received bytes")
		}
		sent, err := number("Bytes Sent")
		if err != nil {
			return nil, fmt.Errorf("invalid sent bytes")
		}
		since, err := number("Connected Since (time_t)")
		if err != nil {
			return nil, fmt.Errorf("invalid connection time")
		}
		cn := get("Common Name")
		if cn == "" {
			return nil, fmt.Errorf("missing client common name")
		}
		result = append(result, Connection{cn, get("Real Address"), get("Virtual Address"), received, sent, since})
	}
	if !valid {
		return nil, fmt.Errorf("invalid OpenVPN status response")
	}
	return result, nil
}

var managedCN = regexp.MustCompile(`^desk-[a-f0-9]{32}$`)

func ValidCN(cn string) bool { return managedCN.MatchString(cn) }

func (c *Client) Disconnect(ctx context.Context, cn string) error {
	if !ValidCN(cn) {
		return fmt.Errorf("invalid managed certificate name")
	}
	connections, err := c.Status(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range connections {
		if entry.CommonName == cn {
			found = true
		}
	}
	if !found {
		return nil
	}
	_, killErr := c.command(ctx, "kill "+cn, false)
	connections, err = c.Status(ctx)
	if err != nil {
		return err
	}
	for _, entry := range connections {
		if entry.CommonName == cn {
			if killErr != nil {
				return killErr
			}
			return fmt.Errorf("client is still connected")
		}
	}
	return nil
}
