package vpnauth

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAP always negotiates TLS before any bind, including ldap:// (StartTLS).
func authenticateLDAP(ctx context.Context, p Provider, username, password string) (bool, error) {
	tc, err := tlsConfig(p.Config)
	if err != nil {
		return false, err
	}
	conn, err := ldap.DialURL(p.Config.Address, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(tc))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return false, ctx.Err()
	}
	conn.SetTimeout(timeout)
	if strings.HasPrefix(p.Config.Address, "ldap://") {
		if err = conn.StartTLS(tc); err != nil {
			return false, err
		}
	}
	if err = conn.Bind(p.Config.BindDN, p.Secret); err != nil {
		return false, err
	}
	filter := strings.ReplaceAll(p.Config.UserFilter, "{username}", ldap.EscapeFilter(username))
	result, err := conn.Search(ldap.NewSearchRequest(p.Config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{"1.1"}, nil))
	if err != nil {
		return false, err
	}
	if len(result.Entries) != 1 {
		return false, nil
	}
	dn := result.Entries[0].DN
	if p.Config.GroupDN != "" {
		filter = strings.NewReplacer("{dn}", ldap.EscapeFilter(dn), "{username}", ldap.EscapeFilter(username)).Replace(p.Config.GroupFilter)
		groups, err := conn.Search(ldap.NewSearchRequest(p.Config.GroupDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, filter, []string{"1.1"}, nil))
		if err != nil {
			return false, err
		}
		if len(groups.Entries) != 1 {
			return false, nil
		}
	}
	if err = conn.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
