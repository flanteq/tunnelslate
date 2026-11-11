package pki

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"tunnelslate/internal/management"
)

func TestCertificateExpirationDateValidation(t *testing.T) {
	now := time.Date(2026, 11, 8, 13, 42, 17, 123, time.UTC)
	ca := now.AddDate(10, 0, 0)
	for _, test := range []struct {
		value string
		valid bool
		want  time.Time
	}{
		{"", true, now.AddDate(0, 0, 825).Truncate(time.Second)},
		{"2026-11-08", true, time.Date(2026, 11, 8, 23, 59, 59, 0, time.UTC)},
		{"2028-02-29", true, time.Date(2028, 2, 29, 23, 59, 59, 0, time.UTC)},
		{"2026-11-07", false, time.Time{}}, {"2026-02-29", false, time.Time{}}, {"2027-13-01", false, time.Time{}},
		{"2037-01-01", false, time.Time{}}, {"2027-1-01", false, time.Time{}}, {"2027-01-01T00:00:00Z", false, time.Time{}},
	} {
		got, err := certificateExpiration(test.value, now, ca)
		if test.valid {
			if err != nil || !got.Equal(test.want) {
				t.Errorf("%q: %v %v", test.value, got, err)
			}
		} else if err == nil {
			t.Errorf("accepted %q", test.value)
		}
	}
	if _, err := certificateExpiration("2027-01-01", now, time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expiry extends beyond the CA")
	}
}

func TestCertificateMaxDateMatchesIssuanceBoundary(t *testing.T) {
	for _, test := range []struct{ caEnd, want string }{
		{"2027-01-01T12:00:00Z", "2026-12-31"},
		{"2028-03-01T00:00:00Z", "2028-02-29"},
		{"2028-02-29T23:59:58Z", "2028-02-28"},
		{"2028-02-29T23:59:59Z", "2028-02-29"},
		{"2028-03-01T00:30:00+03:00", "2028-02-28"},
	} {
		t.Run(test.caEnd, func(t *testing.T) {
			end, err := time.Parse(time.RFC3339, test.caEnd)
			if err != nil {
				t.Fatal(err)
			}
			limit := certificateMaxDate(end)
			if limit != test.want {
				t.Fatalf("got %s, want %s", limit, test.want)
			}
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			if _, err := certificateExpiration(limit, now, end); err != nil {
				t.Fatal("last permitted day rejected", err)
			}
			day, _ := time.Parse("2006-01-02", limit)
			if _, err := certificateExpiration(day.AddDate(0, 0, 1).Format("2006-01-02"), now, end); err == nil {
				t.Fatal("day after limit accepted")
			}
		})
	}
}
func TestCustomCertificateExpiryAndRotationRecovery(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	date := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	first, err := s.StartWithExpiry(ctx, "admin", "expiry-issue-request1", "issue", "client", "Temporary", date)
	if err != nil {
		t.Fatal(err)
	}
	_, args, err := s.operation(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := readCert(s.path("issued", args.CN+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	if cert.NotAfter.UTC().Format("2006-01-02 15:04:05") != date+" 23:59:59" || cert.NotAfter.Unix() != args.ExpiresAt {
		t.Fatal("exact date not applied", cert.NotAfter, args.ExpiresAt)
	}
	if _, err := s.StartWithExpiry(ctx, "admin", "expiry-issue-request1", "issue", "client", "Temporary", time.Now().AddDate(0, 0, 31).Format("2006-01-02")); err == nil {
		t.Fatal("idempotency ignored expiry")
	}
	replay, err := s.StartWithExpiry(ctx, "admin", "expiry-issue-request1", "issue", "client", "Temporary", date)
	if err != nil || replay.ID != first.ID {
		t.Fatal("replay", err)
	}
	m.connect(args.CN)
	s.Management = &management.Client{Socket: filepath.Join(s.RuntimeDir, "missing.sock")}
	nextDate := time.Now().UTC().AddDate(0, 0, 60).Format("2006-01-02")
	rotated, err := s.StartWithExpiry(ctx, "admin", "expiry-rotate-request1", "rotate", first.DeviceID, "", nextDate)
	if err == nil || rotated.State != "partial" || rotated.Step != "disconnect_sessions" {
		t.Fatal("expected partial rotation", err, rotated.State)
	}
	_, newArgs, _ := s.operation(ctx, rotated.ID)
	newCert, _, err := readCert(s.path("issued", newArgs.CN+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	if newCert.NotAfter.UTC().Format("2006-01-02 15:04:05") != nextDate+" 23:59:59" {
		t.Fatal("rotation retained old expiry")
	}
	s.Management = &management.Client{Socket: m.socket}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	done, after, _ := s.operation(ctx, rotated.ID)
	if done.State != "succeeded" || after.ExpiresAt != newArgs.ExpiresAt || done.ResultSerial != rotated.ResultSerial {
		t.Fatal("recovery changed deadline or issued twice")
	}
	checkCRL(t, s, first.ResultSerial)
	var count int
	s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count)
	if count != 2 {
		t.Fatal("duplicated cert on recovery")
	}
}
func TestDefaultCertificateExpiryAndRejectedDatesLeaveNoState(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	before := time.Now().AddDate(0, 0, 825).Unix()
	op, err := s.Start(ctx, "admin", "expiry-default-issue1", "issue", "client", "Default")
	if err != nil {
		t.Fatal(err)
	}
	_, args, _ := s.operation(ctx, op.ID)
	cert, _, err := readCert(s.path("issued", args.CN+".crt"))
	if err != nil || cert.NotAfter.Unix() < before || cert.NotAfter.Unix() > time.Now().AddDate(0, 0, 825).Unix() {
		t.Fatal("wrong default expiry", err)
	}
	for i, value := range []string{"2000-01-01", "invalid", "2099-12-31"} {
		_, err := s.StartWithExpiry(ctx, "admin", []string{"expiry-invalid-one1", "expiry-invalid-two1", "expiry-invalid-three1"}[i], "issue", "client", "Rejected", value)
		var expected *Error
		if !errors.As(err, &expected) || expected.Code != 400 {
			t.Fatal("bad date not rejected", value, err)
		}
	}
	var count int
	s.Store.DB.QueryRow("SELECT count(*) FROM devices").Scan(&count)
	if count != 1 {
		t.Fatal("invalid issuance left a device")
	}
}
func TestUnissuedPastDeadlineIsCancelledRatherThanExtended(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	s.Store.DB.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('late','client','Late','device-late',1)")
	if _, err := s.Store.DB.Exec(`INSERT INTO operations(id,kind,state,step,device_id,client_id,actor,request_key,request_hash,arguments,created_at,updated_at) VALUES ('late-op','issue','pending','queued','late','client','admin','expiry-late-request1','hash','{"cn":"desk-0123456789abcdef0123456789abcdef","old":[],"expires_at":1}',1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	op, _, _ := s.operation(ctx, "late-op")
	if op.State != "failed" || op.Step != "certificate_expired" {
		t.Fatal("late issuance not cancelled", op)
	}
	var count int
	s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count)
	if count != 0 {
		t.Fatal("expired deadline generated credentials")
	}
}
