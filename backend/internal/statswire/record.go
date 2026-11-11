// Package statswire implements the durable handoff between OpenVPN and the panel.
// All counters are cumulative and seen from the VPN client's perspective.
package statswire

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

type Totals struct {
	Sessions int64 `json:"sessions"`
	Duration int64 `json:"duration_seconds"`
	Received int64 `json:"bytes_received"`
	Sent     int64 `json:"bytes_sent"`
}
type Day struct {
	Date string `json:"date"`
	Totals
}
type Record struct {
	ID         string `json:"id"`
	Epoch      string `json:"epoch"`
	CommonName string `json:"common_name"`
	Started    int64  `json:"started_at"`
	Observed   int64  `json:"observed_at"`
	Ended      int64  `json:"ended_at"`
	State      string `json:"state"`
	Totals
	Days []Day `json:"days"`
}

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var cnPattern = regexp.MustCompile(`^desk-[a-f0-9]{32}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }
func NewRecord(id, epoch, cn string, started int64) Record {
	return Record{ID: id, Epoch: epoch, CommonName: cn, Started: started, Observed: started, State: "active", Totals: Totals{Sessions: 1}, Days: []Day{{Date: time.Unix(started, 0).UTC().Format("2006-01-02"), Totals: Totals{Sessions: 1}}}}
}

// Advance splits time exactly at UTC midnight. Bytes straddling a sample boundary
// are apportioned by elapsed time; integer remainders go into the last day.
func (r *Record) Advance(at, received, sent int64) {
	if at < r.Observed {
		return
	}
	if received < r.Received {
		received = r.Received
	}
	if sent < r.Sent {
		sent = r.Sent
	}
	rx, tx := received-r.Received, sent-r.Sent
	from, span := r.Observed, at-r.Observed
	remainingRX, remainingTX := rx, tx
	for from < at {
		day := time.Unix(from, 0).UTC()
		end := day.Truncate(24 * time.Hour).Add(24 * time.Hour).Unix()
		if end > at {
			end = at
		}
		seconds := end - from
		a, b := remainingRX, remainingTX
		if end < at {
			a = proportion(rx, seconds, span)
			b = proportion(tx, seconds, span)
		}
		r.add(day.Format("2006-01-02"), seconds, a, b)
		remainingRX -= a
		remainingTX -= b
		from = end
	}
	if span == 0 && (rx > 0 || tx > 0) {
		r.add(time.Unix(at, 0).UTC().Format("2006-01-02"), 0, rx, tx)
	}
	r.Duration += span
	r.Received = received
	r.Sent = sent
	r.Observed = at
}
func proportion(n, a, b int64) int64 {
	var x, y big.Int
	x.SetInt64(n)
	y.SetInt64(a)
	x.Mul(&x, &y)
	y.SetInt64(b)
	return x.Quo(&x, &y).Int64()
}
func (r *Record) add(date string, duration, rx, tx int64) {
	for i := range r.Days {
		if r.Days[i].Date == date {
			r.Days[i].Duration += duration
			r.Days[i].Received += rx
			r.Days[i].Sent += tx
			return
		}
	}
	r.Days = append(r.Days, Day{Date: date, Totals: Totals{Duration: duration, Received: rx, Sent: tx}})
}
func (r Record) Validate() error {
	if !ValidID(r.ID) || !ValidID(r.Epoch) || !cnPattern.MatchString(r.CommonName) || r.Started < 1 || r.Observed < r.Started || len(r.Days) > 36600 {
		return errors.New("invalid statistics record")
	}
	if (r.State != "active" && r.State != "completed" && r.State != "interrupted") || (r.State == "active" && r.Ended != 0) || (r.State != "active" && r.Ended != r.Observed) {
		return errors.New("invalid statistics state")
	}
	sum := Totals{}
	seen := map[string]bool{}
	for _, d := range r.Days {
		t, err := time.Parse("2006-01-02", d.Date)
		if err != nil || t.Format("2006-01-02") != d.Date || seen[d.Date] || d.Sessions < 0 || d.Duration < 0 || d.Received < 0 || d.Sent < 0 {
			return fmt.Errorf("invalid statistics day")
		}
		seen[d.Date] = true
		sum.Sessions += d.Sessions
		sum.Duration += d.Duration
		sum.Received += d.Received
		sum.Sent += d.Sent
	}
	if r.Sessions != 1 || r.Duration != r.Observed-r.Started || r.Received < 0 || r.Sent < 0 || sum != r.Totals {
		return errors.New("inconsistent statistics counters")
	}
	return nil
}
