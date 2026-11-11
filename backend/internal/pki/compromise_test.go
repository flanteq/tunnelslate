package pki

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
	"tunnelslate/internal/vpnoptions"

	"tunnelslate/internal/ccd"
	"tunnelslate/internal/management"
)

func putLink(t *testing.T, s *Service) {
	t.Helper()
	if _, err := s.Store.DB.Exec("INSERT INTO client_links(client_id,token_hash,created_at) VALUES ('client','test-link-hash',1)"); err != nil {
		t.Fatal(err)
	}
}
func TestCompromiseRevokesAllWithoutReissueOrDeletion(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	laptop, err := s.Start(ctx, "admin", "compromise-laptop01", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	phone, err := s.Start(ctx, "admin", "compromise-phone001", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := s.Start(ctx, "admin", "compromise-rotate01", "rotate", laptop.DeviceID, "")
	if err != nil {
		t.Fatal(err)
	}
	s.Store.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('other','Other',1)")
	other, err := s.Start(ctx, "admin", "compromise-other001", "issue", "other", "Other laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []Operation{laptop, phone, rotated, other} {
		_, args, _ := s.operation(ctx, op.ID)
		m.connect(args.CN)
	}
	putLink(t, s)
	// Taking the PKI lock must not prevent accepting a report.
	unlock, err := s.lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reportCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	op, err := s.ReportCompromise(reportCtx, "admin", "client", "", "", "compromise-report01")
	unlock()
	if err != nil || op.State != "pending" {
		t.Fatal("report waited for PKI or was not queued", err)
	}
	replay, err := s.ReportCompromise(ctx, "admin", "client", "", "", "compromise-report01")
	if err != nil || replay.ID != op.ID {
		t.Fatal("report not idempotent", err)
	}
	_, err = s.Start(ctx, "admin", "compromise-block01", "issue", "client", "Blocked")
	assertConflict(t, err)
	// The job survives a failed disconnect, with link access already closed.
	s.Management = &management.Client{Socket: filepath.Join(s.RuntimeDir, "missing.sock")}
	partial, err := s.Run(ctx, op.ID)
	if err == nil || partial.State != "partial" || partial.Step != "disconnect_sessions" {
		t.Fatalf("unexpected partial: %+v %v", partial, err)
	}
	checkCRL(t, s, laptop.ResultSerial, phone.ResultSerial, rotated.ResultSerial)
	s.Management = &management.Client{Socket: m.socket}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count); err != nil || count != 4 {
		t.Fatal("panic issued replacement certs", err, count)
	}
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM certificates c JOIN devices d ON d.id=c.device_id WHERE d.client_id='client' AND c.status='revoked'").Scan(&count); err != nil || count != 3 {
		t.Fatal("not all historical certs revoked", err, count)
	}
	assertClientDeleted(t, s, "client", false)
	assertDeleted(t, s, laptop.DeviceID, false)
	assertDeleted(t, s, phone.DeviceID, false)
	connections, err := s.Management.Status(ctx)
	_, otherArgs, _ := s.operation(ctx, other.ID)
	if err != nil || len(connections) != 1 || connections[0].CommonName != otherArgs.CN {
		t.Fatal("session isolation", err)
	}
	if _, err := s.Profile(ctx, other.DeviceID, "vpn.test", 1195, "udp", "admin", vpnoptions.Link{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Profile(ctx, laptop.DeviceID, "vpn.test", 1195, "udp", "admin", vpnoptions.Link{}); err == nil {
		t.Fatal("revoked profile available")
	}
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='client.link.compromised' AND severity='CRITICAL'").Scan(&count); err != nil || count != 1 {
		t.Fatal("critical audit not exactly once", err)
	}
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='pki.revoke_client'").Scan(&count); err != nil || count != 1 {
		t.Fatal("completion audit missing", err)
	}
	if _, err := s.Start(ctx, "admin", "compromise-restore1", "rotate", laptop.DeviceID, ""); err != nil {
		t.Fatal("manual recovery blocked", err)
	}
	putLink(t, s)
}
func TestCompromiseCancelsInterruptedIssuanceAndRecoversUnjournaledCertificate(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "interrupted-issue001", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	// Model a crash after Easy-RSA writes the certificate but before DB INSERT.
	if _, err := s.Store.DB.Exec("DELETE FROM certificates WHERE operation_id=?", issued.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec("UPDATE operations SET state='partial',step='issue_certificate',result_serial='' WHERE id=?", issued.ID); err != nil {
		t.Fatal(err)
	}
	putLink(t, s)
	op, err := s.ReportCompromise(ctx, "admin", "client", "", "", "interrupted-report01")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	done, _, err := s.operation(ctx, op.ID)
	if err != nil || done.State != "succeeded" {
		t.Fatal("panic recovery failed", err)
	}
	cancelled, args, err := s.operation(ctx, issued.ID)
	if err != nil || cancelled.State != "failed" || cancelled.Step != "cancelled" {
		t.Fatal("old issuance not cancelled", err)
	}
	checkCRL(t, s, issued.ResultSerial)
	if _, err := s.Run(ctx, issued.ID); err == nil {
		t.Fatal("cancelled issuance retried")
	}
	if _, err := s.Start(ctx, "admin", "interrupted-issue001", "issue", "client", "Phone"); err == nil {
		t.Fatal("replay resurrected old issuance")
	}
	var status string
	if err := s.Store.DB.QueryRow("SELECT status FROM certificates WHERE serial=?", issued.ResultSerial).Scan(&status); err != nil || status != "revoked" {
		t.Fatal("unjournaled certificate not recovered and revoked", err)
	}
	// Subsequent manual rotation uses a distinct operation and remains possible.
	restored, err := s.Start(ctx, "admin", "interrupted-restore01", "rotate", issued.DeviceID, "")
	if err != nil {
		t.Fatal(err)
	}
	_, newArgs, _ := s.operation(ctx, restored.ID)
	if args.CN == newArgs.CN {
		t.Fatal("new profile reused compromised identity")
	}
}
func TestCompromiseCancelsPendingWorkBeforeAnyCertificateExists(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	putLink(t, s)
	s.Store.DB.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('pending-device','client','Pending','device-pending',1)")
	data, _ := json.Marshal(Arguments{CN: "desk-0123456789abcdef0123456789abcdef", Old: []Reference{}})
	if _, err := s.Store.DB.Exec(`INSERT INTO operations(id,kind,state,step,device_id,client_id,actor,request_key,request_hash,arguments,created_at,updated_at) VALUES ('pending-issue','issue','pending','queued','pending-device','client','admin','pending-issue-key01','hash',?,1,1)`, string(data)); err != nil {
		t.Fatal(err)
	}
	op, err := s.ReportCompromise(ctx, "admin", "client", "", "", "pending-report-key01")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, _, _ := s.operation(ctx, "pending-issue")
	if cancelled.State != "failed" {
		t.Fatal("queued issue survived")
	}
	completed, _, _ := s.operation(ctx, op.ID)
	if completed.State != "succeeded" {
		t.Fatal("empty panic did not complete")
	}
	var count int
	s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count)
	if count != 0 {
		t.Fatal("panic issued certificate")
	}
}

func TestCompromiseDuringIssuanceIncludesCertificateWrittenAfterReport(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	putLink(t, s)
	var report Operation
	var reportErr error
	reported := false
	s.Changed = func(_ ...string) {
		if reported {
			return
		}
		var issuing bool
		if err := s.Store.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM operations WHERE kind='issue' AND state='running' AND step='issue_certificate')").Scan(&issuing); err != nil {
			t.Error(err)
			return
		}
		if !issuing {
			return
		}
		reported = true
		// Called from inside the running operation, with the PKI lock held. The
		// acceptance path must not wait for that lock or miss the future cert.
		report, reportErr = s.ReportCompromise(ctx, "admin", "client", "", "", "concurrent-report001")
	}
	issued, err := s.Start(ctx, "admin", "concurrent-issue0001", "issue", "client", "Phone")
	s.Changed = nil
	if err != nil || !reported || reportErr != nil {
		t.Fatal("report during issuance failed", err, reportErr)
	}
	if _, err := s.Profile(ctx, issued.DeviceID, "vpn.test", 1195, "udp", "admin", vpnoptions.Link{}); err == nil {
		t.Fatal("profile exposed while emergency revocation queued")
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	checkCRL(t, s, issued.ResultSerial)
	done, _, err := s.operation(ctx, report.ID)
	if err != nil || done.State != "succeeded" {
		t.Fatal("late issuance escaped revocation", err)
	}
}

func TestCompromisePreservesCCDAndReservations(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "ccd-compromise-issue1", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	enableCCD(t, s)
	v := ccd.Defaults()
	v.StaticIP = "10.8.0.200"
	if _, err := s.SaveDeviceCCD(ctx, issued.DeviceID, v, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	putLink(t, s)
	if _, err := s.ReportCompromise(ctx, "admin", "client", "", "", "ccd-compromise-report1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDeviceCCD(ctx, issued.DeviceID, v, 1, "admin"); err == nil {
		t.Fatal("CCD changed during emergency operation")
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var address string
	if err := s.Store.DB.QueryRow("SELECT static_ip FROM device_ccd WHERE device_id=?", issued.DeviceID).Scan(&address); err != nil || address != v.StaticIP {
		t.Fatal("CCD reservation lost", err)
	}
	if _, err := s.Start(ctx, "admin", "ccd-compromise-restore1", "rotate", issued.DeviceID, ""); err != nil {
		t.Fatal("manual restore with CCD failed", err)
	}
	if err := s.Store.DB.QueryRow("SELECT static_ip FROM device_ccd WHERE device_id=?", issued.DeviceID).Scan(&address); err != nil || address != v.StaticIP {
		t.Fatal("restored device lost settings", err)
	}
}
