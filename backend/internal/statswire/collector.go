package statswire

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tunnelslate/internal/management"
)

type Collector struct{ Queue, Runtime string }
type localState struct {
	Record  Record `json:"record"`
	Pending bool   `json:"pending"`
}

func (c Collector) statePath(cn string) string { return filepath.Join(c.Runtime, cn+".json") }
func (c Collector) publish(s *localState) error {
	// The panel may commit and acknowledge a final record before our local
	// journal clears Pending. A durable acknowledgement closes that crash window,
	// including when session history has already expired or was deleted.
	if s.Record.State != "active" {
		if _, err := os.Stat(Acknowledgement(c.Queue, s.Record.ID)); err == nil {
			s.Pending = false
			return Write(c.statePath(s.Record.CommonName), s)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	s.Pending = true
	if err := Write(c.statePath(s.Record.CommonName), s); err != nil {
		return err
	}
	if err := Write(filepath.Join(c.Queue, s.Record.ID+".json"), s.Record); err != nil {
		return err
	}
	s.Pending = false
	return Write(c.statePath(s.Record.CommonName), s)
}

// Once the producer has durably cleared Pending (or its old epoch is gone),
// acknowledgements no longer need to be retained as a per-session ledger.
func (c Collector) cleanupAcknowledgements() error {
	needed := map[string]bool{}
	if err := c.each(func(s *localState) error {
		if s.Pending {
			needed[s.Record.ID] = true
		}
		return nil
	}); err != nil {
		return err
	}
	entries, err := os.ReadDir(c.Queue)
	if err != nil {
		return err
	}
	for _, e := range entries {
		id := strings.TrimPrefix(e.Name(), ".ack-")
		if e.Name() == ".ack-"+id && ValidID(id) && !needed[id] {
			if err = os.Remove(filepath.Join(c.Queue, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c Collector) each(fn func(*localState) error) error {
	entries, err := os.ReadDir(c.Runtime)
	if err != nil {
		return err
	}
	for _, e := range entries {
		cn := strings.TrimSuffix(e.Name(), ".json")
		if !cnPattern.MatchString(cn) {
			continue
		}
		var s localState
		if err = Read(c.statePath(cn), &s); err != nil {
			return err
		}
		if err = fn(&s); err != nil {
			return err
		}
	}
	return nil
}

// Start seals the previous process epoch at its last saved checkpoint. Downtime
// must never be counted as connection time.
func (c Collector) Start() error {
	return Locked(c.Queue, func() error {
		if err := os.MkdirAll(c.Runtime, 0700); err != nil {
			return err
		}
		names, err := Records(c.Queue)
		if err != nil {
			return err
		}
		for _, name := range names {
			var r Record
			if err = Read(filepath.Join(c.Queue, name), &r); err != nil {
				return err
			}
			if err = r.Validate(); err != nil {
				return err
			}
			if r.State == "active" {
				r.State = "interrupted"
				r.Ended = r.Observed
				if err = Write(filepath.Join(c.Queue, name), r); err != nil {
					return err
				}
			}
		}
		// Retry any write interrupted between the local journal and queue publication.
		if err = c.each(func(s *localState) error {
			if s.Record.State == "active" {
				s.Record.State = "interrupted"
				s.Record.Ended = s.Record.Observed
				s.Pending = true
			}
			if s.Pending {
				return c.publish(s)
			}
			return nil
		}); err != nil {
			return err
		}
		entries, err := os.ReadDir(c.Runtime)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if cnPattern.MatchString(strings.TrimSuffix(e.Name(), ".json")) {
				if err = os.Remove(filepath.Join(c.Runtime, e.Name())); err != nil {
					return err
				}
			}
		}
		epoch, err := RandomID()
		if err != nil {
			return err
		}
		if err = c.cleanupAcknowledgements(); err != nil {
			return err
		}
		return Write(filepath.Join(c.Runtime, "epoch"), epoch)
	})
}
func (c Collector) Connect(cn string, started int64) error {
	if !cnPattern.MatchString(cn) || started <= 0 {
		return errors.New("invalid statistics connection")
	}
	return Locked(c.Queue, func() error {
		var epoch string
		if err := Read(filepath.Join(c.Runtime, "epoch"), &epoch); err != nil {
			return err
		}
		var prior localState
		if err := Read(c.statePath(cn), &prior); err == nil {
			if prior.Pending {
				if err = c.publish(&prior); err != nil {
					return err
				}
			}
			if prior.Record.State == "active" {
				prior.Record.State = "interrupted"
				prior.Record.Ended = prior.Record.Observed
				if err = c.publish(&prior); err != nil {
					return err
				}
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		id, err := RandomID()
		if err != nil {
			return err
		}
		s := localState{Record: NewRecord(id, epoch, cn, started)}
		return c.publish(&s)
	})
}
func (c Collector) Disconnect(cn string, started, at, received, sent int64) error {
	if !cnPattern.MatchString(cn) {
		return errors.New("invalid statistics common name")
	}
	return Locked(c.Queue, func() error {
		var s localState
		if err := Read(c.statePath(cn), &s); err != nil {
			return err
		}
		// An obsolete disconnect must not close a replacement connection.
		if s.Record.State != "active" || (started > 0 && started != s.Record.Started) {
			return nil
		}
		s.Record.Advance(at, received, sent)
		s.Record.State = "completed"
		s.Record.Ended = s.Record.Observed
		return c.publish(&s)
	})
}
func (c Collector) Sample(body string) error {
	// Native status writes are not atomic. Require END and a complete parse before
	// using a snapshot; incomplete files simply wait for the next supervisor tick.
	if !strings.HasSuffix(strings.TrimSpace(body), "END") {
		return nil
	}
	connections, err := management.ParseStatus(strings.Split(body, "\n"))
	if err != nil {
		return err
	}
	var at int64
	for _, line := range strings.Split(body, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) >= 3 && f[0] == "TIME" {
			at, _ = strconv.ParseInt(f[len(f)-1], 10, 64)
		}
	}
	if at <= 0 {
		return errors.New("statistics status has no timestamp")
	}
	return Locked(c.Queue, func() error {
		// A pending final event must be retried even after it disappeared from status.
		if err := c.each(func(s *localState) error {
			if s.Pending {
				return c.publish(s)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := c.cleanupAcknowledgements(); err != nil {
			return err
		}
		for _, v := range connections {
			if !cnPattern.MatchString(v.CommonName) {
				continue
			}
			var s localState
			if err = Read(c.statePath(v.CommonName), &s); os.IsNotExist(err) {
				var epoch string
				if err = Read(filepath.Join(c.Runtime, "epoch"), &epoch); err != nil {
					return err
				}
				id, e := RandomID()
				if e != nil {
					return e
				}
				s.Record = NewRecord(id, epoch, v.CommonName, v.ConnectedSince)
			} else if err != nil {
				return err
			}
			if s.Record.State != "active" || at <= s.Record.Observed {
				continue
			}
			// status counters are server-centric: receive means the client sent data.
			s.Record.Advance(at, v.BytesSent, v.BytesReceived)
			if err = c.publish(&s); err != nil {
				return err
			}
		}
		return nil
	})
}
func (c Collector) Stop() error {
	return Locked(c.Queue, func() error {
		return c.each(func(s *localState) error {
			if s.Record.State == "active" {
				s.Record.State = "interrupted"
				s.Record.Ended = s.Record.Observed
				return c.publish(s)
			}
			if s.Pending {
				return c.publish(s)
			}
			return nil
		})
	})
}
