package pki

import "time"

const DefaultCertificateDays = 825

// A selected day grants access until 23:59:59 UTC. Only complete days fit
// within the CA lifetime, including its final day when it ends at 23:59:59.
func certificateMaxDate(caEnd time.Time) string {
	return caEnd.UTC().Add(time.Second).Truncate(24 * time.Hour).Add(-24 * time.Hour).Format("2006-01-02")
}

func (s *Service) CertificateMaxDate() string {
	if s.PKIDir == "" {
		return ""
	}
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil || !ca.IsCA {
		return ""
	}
	return certificateMaxDate(ca.NotAfter)
}

// Dates are inclusive in UTC: an access grant for a date ends at 23:59:59Z.
// The resolved instant is journaled once, so retries never extend the grant.
func certificateExpiration(value string, now, caEnd time.Time) (time.Time, error) {
	end := now.UTC().AddDate(0, 0, DefaultCertificateDays).Truncate(time.Second)
	if value != "" {
		day, err := time.Parse("2006-01-02", value)
		if err != nil || day.Format("2006-01-02") != value {
			return time.Time{}, problem(400, "Дата окончания должна быть в формате ГГГГ-ММ-ДД")
		}
		end = day.AddDate(0, 0, 1).Add(-time.Second)
	}
	if !end.After(now) {
		return time.Time{}, problem(400, "Дата окончания сертификата уже прошла")
	}
	if end.After(caEnd) {
		return time.Time{}, problem(400, "Срок сертификата не может превышать срок центра сертификации: "+caEnd.UTC().Format("02.01.2006 15:04 UTC"))
	}
	return end, nil
}
