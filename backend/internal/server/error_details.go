package server

import (
	"regexp"
	"strings"
	"time"
)

var staticIPRangeError = regexp.MustCompile(`^Постоянный VPN-IP должен быть в диапазоне (\S+)–(\S+)$`)
var subnetConflictError = regexp.MustCompile(`^Новая подсеть несовместима с постоянным IP устройства «(.*)». Сначала измените или сбросьте его IP\.$`)

func apiErrorDetails(status int, message string) (string, map[string]any) {
	if code, ok := apiErrorCodes[message]; ok {
		return code, nil
	}
	if matches := staticIPRangeError.FindStringSubmatch(message); matches != nil {
		return "ccd.static_ip_range", map[string]any{"start": matches[1], "end": matches[2]}
	}
	if matches := subnetConflictError.FindStringSubmatch(message); matches != nil {
		return "vpn.static_ip_conflict", map[string]any{"device": matches[1]}
	}
	const caPrefix = "Срок сертификата не может превышать срок центра сертификации: "
	if date, ok := strings.CutPrefix(message, caPrefix); ok {
		if limit, err := time.Parse("02.01.2006 15:04 MST", date); err == nil {
			return "certificate.ca_expiry", map[string]any{"expires_at": limit.Unix()}
		}
	}
	const incompletePrefix = "Incomplete existing PKI: missing or invalid "
	if file, ok := strings.CutPrefix(message, incompletePrefix); ok {
		file = strings.TrimSuffix(file, ". Restore or repair it; automatic reset is disabled.")
		return "pki.incomplete", map[string]any{"file": file}
	}
	if status >= 500 {
		return "internal_error", nil
	}
	return "request_failed", nil
}
