package pki

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"tunnelslate/internal/management"
)

// ReportCompromise records the critical event, closes access and queues durable
// revocation in ONE transaction. It must not wait for the filesystem/PKI lock.
// expectedLink and sessionHash are required for a report from a public session.
func (s *Service) ReportCompromise(ctx context.Context, actor, clientID, expectedLink, sessionHash, key string) (Operation, error) {
	if !requestKey.MatchString(key) {
		return Operation{}, problem(400, "A 16–80 character Idempotency-Key is required")
	}
	s.Store.LinkMu.Lock()
	defer s.Store.LinkMu.Unlock()
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	sum := sha256.Sum256([]byte("revoke_client\x00" + clientID))
	fingerprint := hex.EncodeToString(sum[:])
	var existing, previous, previousActor string
	err = tx.QueryRowContext(ctx, "SELECT id,request_hash,actor FROM operations WHERE request_key=?", key).Scan(&existing, &previous, &previousActor)
	if err == nil {
		if previous != fingerprint || previousActor != actor {
			return Operation{}, problem(409, "Idempotency-Key was used for a different request")
		}
		if err := tx.Commit(); err != nil {
			return Operation{}, err
		}
		op, _, err := s.operation(ctx, existing)
		return op, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Operation{}, err
	}
	var link string
	err = tx.QueryRowContext(ctx, `SELECT l.token_hash FROM client_links l JOIN clients c ON c.id=l.client_id WHERE l.client_id=? AND c.deleted_at IS NULL AND c.disabled=0`, clientID).Scan(&link)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, problem(404, "Client link is unavailable")
	}
	if err != nil {
		return Operation{}, err
	}
	if expectedLink != "" {
		var valid bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM client_link_sessions WHERE token_hash=? AND client_id=? AND link_hash=? AND expires_at>?)`, sessionHash, clientID, link, time.Now().Unix()).Scan(&valid); err != nil {
			return Operation{}, err
		}
		if link != expectedLink || !valid {
			return Operation{}, problem(401, "Client link is unavailable")
		}
	}
	opID, err := id()
	if err != nil {
		return Operation{}, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,kind,state,step,client_id,actor,request_key,request_hash,arguments,created_at,updated_at) VALUES (?,'revoke_client','pending','queued',?,?,?,?,?, ?,?)`, opID, clientID, actor, key, fingerprint, `{"old":[]}`, now, now); err != nil {
		return Operation{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,severity,created_at) VALUES (?,'client.link.compromised',?,'CRITICAL',?)", actor, clientID, now); err != nil {
		return Operation{}, err
	}
	// ON DELETE CASCADE invalidates ALL sessions, including other browsers.
	if _, err := tx.ExecContext(ctx, "DELETE FROM client_links WHERE client_id=?", clientID); err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, err
	}
	slog.Error("Client link compromised; certificate revocation requested", "severity", "CRITICAL", "client_id", clientID, "operation_id", opID, "actor", actor)
	s.notify("clients", "devices", "operations", "audit")
	op, _, err := s.operation(ctx, opID)
	return op, err
}

// Called under the PKI lock. An operation that was already running when the
// report arrived has now stopped; collect even certificates issued after the
// report. Cancel unfinished work so recovery cannot issue new credentials later.
func (s *Service) prepareClientRevocation(ctx context.Context, op Operation) (Arguments, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT id,COALESCE(device_id,''),arguments FROM operations WHERE client_id=? AND id!=? AND state IN ('pending','running','partial','failed')`, op.ClientID, op.ID)
	if err != nil {
		return Arguments{}, err
	}
	type interrupted struct {
		id, device string
		args       Arguments
	}
	jobs := []interrupted{}
	for rows.Next() {
		var job interrupted
		var data string
		if err := rows.Scan(&job.id, &job.device, &data); err != nil {
			rows.Close()
			return Arguments{}, err
		}
		if err := json.Unmarshal([]byte(data), &job.args); err != nil {
			rows.Close()
			return Arguments{}, err
		}
		jobs = append(jobs, job)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Arguments{}, err
	}
	for _, job := range jobs {
		// Recover a cert written by Easy-RSA just before its DB insert failed.
		if job.args.CN != "" {
			if !management.ValidCN(job.args.CN) {
				return Arguments{}, errors.New("invalid interrupted certificate reference")
			}
			cert, _, err := readCert(s.path("issued", job.args.CN+".crt"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return Arguments{}, err
			}
			if err == nil {
				if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name,operation_id) VALUES (?,?,'valid',?,?,?,?) ON CONFLICT(serial) DO NOTHING`, Serial(cert.SerialNumber), job.device, cert.NotBefore.Unix(), cert.NotAfter.Unix(), job.args.CN, job.id); err != nil {
					return Arguments{}, err
				}
			}
		}
		if _, err := s.Store.DB.ExecContext(ctx, `UPDATE operations SET state='failed',step='cancelled',error='Cancelled after client link compromise',updated_at=? WHERE id=? AND state IN ('pending','running','partial')`, time.Now().Unix(), job.id); err != nil {
			return Arguments{}, err
		}
	}
	args := Arguments{Old: []Reference{}}
	rows, err = s.Store.DB.QueryContext(ctx, `SELECT c.serial,c.common_name FROM certificates c JOIN devices d ON d.id=c.device_id WHERE d.client_id=? ORDER BY c.rowid`, op.ClientID)
	if err != nil {
		return args, err
	}
	for rows.Next() {
		var ref Reference
		if err := rows.Scan(&ref.Serial, &ref.CN); err != nil {
			rows.Close()
			return args, err
		}
		args.Old = append(args.Old, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return args, err
	}
	data, err := json.Marshal(args)
	if err != nil {
		return args, err
	}
	_, err = s.Store.DB.ExecContext(ctx, "UPDATE operations SET arguments=? WHERE id=?", string(data), op.ID)
	return args, err
}
