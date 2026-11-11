package statswire

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testCN = "desk-0123456789abcdef0123456789abcdef"

func stamp(s string) int64 { v, _ := time.Parse(time.RFC3339, s); return v.Unix() }
func TestDailySplittingAndMonotonicCounters(t *testing.T) {
	r := NewRecord(strings.Repeat("a", 32), strings.Repeat("b", 32), testCN, stamp("2026-11-10T23:59:50Z"))
	r.Advance(r.Started+20, 101, 201)
	if len(r.Days) != 2 || r.Days[0].Duration != 10 || r.Days[1].Duration != 10 || r.Days[0].Received+r.Days[1].Received != 101 || r.Days[0].Sent+r.Days[1].Sent != 201 || r.Days[0].Sessions != 1 || r.Days[1].Sessions != 0 {
		t.Fatalf("bad split: %+v", r)
	}
	r.Advance(r.Observed-5, 1000, 2000)
	r.Advance(r.Observed, 1, 1)
	if r.Received != 101 || r.Sent != 201 || r.Duration != 20 {
		t.Fatal("counters regressed", r)
	}
	r.Advance(r.Observed, 111, 211)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Days {
		if d.Duration < 0 {
			t.Fatal("negative duration")
		}
	}
}
func status(at, since, rx, tx int64) string {
	return fmt.Sprintf("TITLE\tOpenVPN\nTIME\tdate\t%d\nHEADER\tCLIENT_LIST\tCommon Name\tBytes Received\tBytes Sent\tConnected Since (time_t)\nCLIENT_LIST\t%s\t%d\t%d\t%d\nEND\n", at, testCN, rx, tx, since)
}
func TestCollectorDurableFinalReconnectAndRestart(t *testing.T) {
	root := t.TempDir()
	c := Collector{Queue: filepath.Join(root, "queue"), Runtime: filepath.Join(root, "runtime")}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(testCN, 100); err != nil {
		t.Fatal(err)
	}
	if err := c.Sample(status(110, 100, 200, 400)); err != nil {
		t.Fatal(err)
	}
	var state localState
	if err := Read(c.statePath(testCN), &state); err != nil {
		t.Fatal(err)
	}
	id := state.Record.ID
	if state.Record.Received != 400 || state.Record.Sent != 200 || state.Record.Duration != 10 {
		t.Fatal("wrong counter direction", state)
	}
	if err := c.Disconnect(testCN, 100, 111, 450, 250); err != nil {
		t.Fatal(err)
	}
	var final Record
	if err := Read(filepath.Join(c.Queue, id+".json"), &final); err != nil {
		t.Fatal(err)
	}
	if final.State != "completed" || final.Duration != 11 || final.Sent != 250 {
		t.Fatal("wrong final", final)
	}
	// Acknowledgement followed by a stale status must not recreate a final event.
	if err := os.Remove(filepath.Join(c.Queue, id+".json")); err != nil {
		t.Fatal(err)
	}
	if err := c.Sample(status(115, 100, 200, 400)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.Queue, id+".json")); !os.IsNotExist(err) {
		t.Fatal("replayed terminal session", err)
	}
	if err := c.Connect(testCN, 120); err != nil {
		t.Fatal(err)
	}
	if err := c.Sample(status(130, 120, 10, 20)); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(testCN, 100, 140, 9000, 9000); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	names, err := Records(c.Queue)
	if err != nil || len(names) != 1 {
		t.Fatal(names, err)
	}
	if err = Read(filepath.Join(c.Queue, names[0]), &final); err != nil {
		t.Fatal(err)
	}
	if final.State != "interrupted" || final.Duration != 10 || final.Received != 20 || final.ID == id {
		t.Fatal("bad restart recovery", final)
	}
}
func TestShortSessionWithoutStatusAndPartialStatus(t *testing.T) {
	c := Collector{Queue: filepath.Join(t.TempDir(), "queue"), Runtime: t.TempDir()}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(testCN, 100); err != nil {
		t.Fatal(err)
	}
	if err := c.Sample(strings.TrimSuffix(status(110, 100, 123, 456), "END\n")); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(testCN, 100, 101, 9, 7); err != nil {
		t.Fatal(err)
	}
	names, _ := Records(c.Queue)
	var r Record
	if err := Read(filepath.Join(c.Queue, names[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Duration != 1 || r.Sent != 7 || r.Received != 9 || r.State != "completed" {
		t.Fatal(r)
	}
}

func TestAcknowledgedFinalDoesNotReplayAfterLocalJournalFailure(t *testing.T) {
	c := Collector{Queue: filepath.Join(t.TempDir(), "queue"), Runtime: t.TempDir()}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(testCN, 100); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(testCN, 100, 101, 10, 20); err != nil {
		t.Fatal(err)
	}
	var s localState
	if err := Read(c.statePath(testCN), &s); err != nil {
		t.Fatal(err)
	}
	// Simulate a failed journal update after publication, followed by the panel's
	// successful transaction/ack and detailed-history deletion/retention.
	s.Pending = true
	if err := Write(c.statePath(testCN), s); err != nil {
		t.Fatal(err)
	}
	if err := Write(Acknowledgement(c.Queue, s.Record.ID), s.Record.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(c.Queue, s.Record.ID+".json")); err != nil {
		t.Fatal(err)
	}
	if err := c.Sample(status(110, 100, 1, 2)); err != nil {
		t.Fatal(err)
	}
	names, err := Records(c.Queue)
	if err != nil || len(names) != 0 {
		t.Fatal("acknowledged final replayed", names, err)
	}
	if err = Read(c.statePath(testCN), &s); err != nil || s.Pending {
		t.Fatal("pending state not cleared", s, err)
	}
	if _, err = os.Stat(Acknowledgement(c.Queue, s.Record.ID)); !os.IsNotExist(err) {
		t.Fatal("unneeded acknowledgement retained", err)
	}
}
