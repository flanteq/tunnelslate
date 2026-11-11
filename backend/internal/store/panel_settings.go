package store

import (
	"context"
	"errors"
	"time"
)

var ErrPanelRevision = errors.New("panel settings changed")

type PanelSettings struct {
	InstanceName   string `json:"instance_name"`
	MetricsEnabled bool   `json:"metrics_enabled"`
	MetricsMTLS    bool   `json:"metrics_mtls"`
	MetricsSource  string `json:"metrics_source"`
	ServerCert     string `json:"server_cert_pem"`
	ClientCA       string `json:"client_ca_pem"`
	KeyConfigured  bool   `json:"key_configured"`
	EncryptedKey   string `json:"-"`
	Revision       int64  `json:"revision"`
}

func (s *Store) PanelSettings(ctx context.Context) (p PanelSettings, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT instance_name,metrics_enabled,metrics_mtls,metrics_source,server_cert,client_ca,encrypted_key,revision FROM panel_settings WHERE id=1`).Scan(&p.InstanceName, &p.MetricsEnabled, &p.MetricsMTLS, &p.MetricsSource, &p.ServerCert, &p.ClientCA, &p.EncryptedKey, &p.Revision)
	p.KeyConfigured = p.EncryptedKey != ""
	return
}

func (s *Store) SavePanelSettings(ctx context.Context, p PanelSettings, actor, action string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE panel_settings SET instance_name=?,metrics_enabled=?,metrics_mtls=?,metrics_source=?,server_cert=?,client_ca=?,encrypted_key=?,revision=revision+1 WHERE id=1 AND revision=?`, p.InstanceName, p.MetricsEnabled, p.MetricsMTLS, p.MetricsSource, p.ServerCert, p.ClientCA, p.EncryptedKey, p.Revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPanelRevision
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,?,?,?)`, actor, action, "panel", time.Now().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}
