package management

import (
	"testing"
)

func TestDCOActualStateIsIndependentOfBuildFlag(t *testing.T) {
	for _, tc := range []struct {
		name           string
		lines          []string
		known, enabled bool
	}{
		{"compiled only", []string{"TITLE\tOpenVPN 2.7.7 [DCO]"}, false, false},
		{"enabled", []string{"GLOBAL_STATS\tdco_enabled\t1"}, true, true},
		{"compiled but disabled", []string{"TITLE\tOpenVPN 2.7.7 [DCO]", "GLOBAL_STATS\tdco_enabled\t0"}, true, false},
		{"malformed", []string{"GLOBAL_STATS\tdco_enabled\tyes"}, false, false},
		{"duplicate", []string{"GLOBAL_STATS\tdco_enabled\t1", "GLOBAL_STATS\tdco_enabled\t0"}, false, false},
		{"truncated", []string{"GLOBAL_STATS\tdco_enabled"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := statusDCO(tc.lines)
			if (got != nil) != tc.known || (got != nil && *got != tc.enabled) {
				t.Fatalf("state=%v known=%v enabled=%v", got, tc.known, tc.enabled)
			}
		})
	}
}

func TestStatusVersion(t *testing.T) {
	for _, tc := range []struct{ title, want string }{
		{"OpenVPN 2.6.20 x86_64-alpine-linux-musl [SSL (OpenSSL)]", "2.6.20"},
		{"OpenVPN 2.7.7 x86_64-alpine-linux-musl [SSL (OpenSSL)] [DCO]", "2.7.7"},
		{"OpenVPN 2.7.9", "2.7.9"},
		{"OpenVPN 2.7_rc6 x86_64-linux-gnu", "2.7_rc6"},
		{"OpenVPN 2.8_git x86_64-linux-gnu", "2.8_git"},
		{"OpenVPN", ""},
		{"OpenVPN test", ""},
		{"Other server 2.7.7", ""},
	} {
		t.Run(tc.title, func(t *testing.T) {
			rows := []string{"TIME\tSun Nov 8 12:00:00 2026\t1794139200", "TITLE\t" + tc.title}
			if got := statusVersion(rows); got != tc.want {
				t.Fatalf("version=%q, want %q", got, tc.want)
			}
			if _, err := ParseStatus(rows); err != nil {
				t.Fatal("missing or unknown version broke connection status", err)
			}
		})
	}
	if got := statusVersion([]string{"CLIENT_LIST\tOpenVPN 2.7.7"}); got != "" {
		t.Fatal("client data was mistaken for the server version", got)
	}
}

func TestParseStatusUsesHeaders(t *testing.T) {
	rows := []string{"TITLE\tOpenVPN 2.6.20", "HEADER\tCLIENT_LIST\tBytes Sent\tCommon Name\tReal Address\tBytes Received\tVirtual Address\tConnected Since (time_t)", "CLIENT_LIST\t456\tdesk-0123456789abcdef0123456789abcdef\t198.51.100.1:2000\t123\t10.8.0.2\t1700000000"}
	got, err := ParseStatus(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].BytesSent != 456 || got[0].BytesReceived != 123 || got[0].VirtualAddress != "10.8.0.2" || got[0].ConnectedSince != 1700000000 {
		t.Fatalf("unexpected connection: %+v", got)
	}
	if _, err := ParseStatus([]string{"not a status"}); err == nil {
		t.Fatal("invalid status accepted")
	}
	if !ValidCN(got[0].CommonName) || ValidCN("desk-test\nkill all") {
		t.Fatal("CN validation")
	}
}
