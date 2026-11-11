package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (s *Store) TOTPKeyPath() string {
	return filepath.Join(filepath.Dir(s.initialPasswordPath), "totp.key")
}

func readTOTPKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != 65 {
		return nil, errors.New("invalid TOTP encryption key file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSuffix(string(data), "\n"))
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid TOTP encryption key file")
	}
	return key, nil
}

// Never replace a missing key if the database already contains encrypted
// secrets. A database and its key must be restored from a consistent backup.
func (s *Store) ensureTOTPKey(ctx context.Context) ([]byte, error) {
	path := s.TOTPKeyPath()
	if key, err := readTOTPKey(path); !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	var exists bool
	if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM admin_totp UNION ALL SELECT 1 FROM admin_totp_setups)`).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("TOTP encryption key is missing; restore totp.key with its database")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".totp-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	return readTOTPKey(path)
}

func totpCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) SealTOTPSecret(ctx context.Context, adminID int64, secret string) (string, error) {
	key, err := s.ensureTOTPKey(ctx)
	if err != nil {
		return "", err
	}
	aead, err := totpCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	data := aead.Seal(nonce, nonce, []byte(secret), secretContext(fmt.Sprintf("totp/%d", adminID)))
	return base64.RawStdEncoding.EncodeToString(data), nil
}

// Opening a secret only reads the key, so it is safe inside a SQL transaction.
func (s *Store) OpenTOTPSecret(adminID int64, encoded string) (string, error) {
	key, err := readTOTPKey(s.TOTPKeyPath())
	if err != nil {
		return "", fmt.Errorf("read TOTP encryption key: %w", err)
	}
	aead, err := totpCipher(key)
	if err != nil {
		return "", err
	}
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(data) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("invalid encrypted TOTP secret")
	}
	secret, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], secretContext(fmt.Sprintf("totp/%d", adminID)))
	if err != nil {
		return "", errors.New("could not decrypt TOTP secret; restore totp.key with its database")
	}
	return string(secret), nil
}
