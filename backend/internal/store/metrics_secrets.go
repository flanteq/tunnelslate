package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

func (s *Store) MetricsKeyPath() string {
	return filepath.Join(filepath.Dir(s.initialPasswordPath), "metrics.key")
}

func (s *Store) metricsKey(ctx context.Context) ([]byte, error) {
	path := s.MetricsKeyPath()
	if key, err := readTOTPKey(path); !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	var exists bool
	if err := s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM panel_settings WHERE encrypted_key!='')").Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("metrics TLS key is missing; restore metrics.key with its database")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".metrics-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.WriteString(hex.EncodeToString(key) + "\n"); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err = syncDirectory(path); err != nil {
		return nil, err
	}
	return readTOTPKey(path)
}
func (s *Store) SealMetricsSecret(ctx context.Context, id, secret string) (string, error) {
	key, err := s.metricsKey(ctx)
	if err != nil {
		return "", err
	}
	aead, err := totpCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(secret), secretContext("metrics/"+id))), nil
}
func (s *Store) OpenMetricsSecret(id, encoded string) (string, error) {
	key, err := readTOTPKey(s.MetricsKeyPath())
	if err != nil {
		return "", errors.New("cannot read metrics.key")
	}
	aead, err := totpCipher(key)
	if err != nil {
		return "", err
	}
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(b) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("invalid encrypted metrics TLS secret")
	}
	secret, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], secretContext("metrics/"+id))
	if err != nil {
		return "", errors.New("cannot decrypt metrics TLS secret")
	}
	return string(secret), nil
}
