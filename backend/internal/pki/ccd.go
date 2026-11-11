package pki

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"tunnelslate/internal/networkpolicy"

	"tunnelslate/internal/ccd"
	"tunnelslate/internal/management"
)

type CCDView struct {
	Settings         ccd.Settings `json:"settings"`
	VPN              ccd.Global   `json:"vpn"`
	DynamicRange     ccd.Range    `json:"dynamic_range"`
	StaticRange      ccd.Range    `json:"static_range"`
	Published        bool         `json:"published"`
	PublicationError string       `json:"publication_error"`
}

func (s *Service) ccdGlobal(ctx context.Context) (ccd.Global, error) {
	g := ccd.Global{DNSSearch: []string{}}
	var data string
	err := s.Store.DB.QueryRowContext(ctx, "SELECT configuration,revision FROM vpn_settings WHERE id=1").Scan(&data, &g.Revision)
	if err != nil {
		return g, err
	}
	revision := g.Revision
	err = json.Unmarshal([]byte(data), &g)
	g.Revision = revision
	return g, err
}

func (s *Service) DeviceCCD(ctx context.Context, deviceID string) (CCDView, error) {
	v := CCDView{Settings: ccd.Defaults()}
	var exists int
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT count(*) FROM devices d JOIN clients c ON c.id=d.client_id WHERE d.id=? AND d.deleted_at IS NULL AND c.deleted_at IS NULL`, deviceID).Scan(&exists); err != nil {
		return v, err
	}
	if exists == 0 {
		return v, problem(404, "Устройство не найдено")
	}
	g, err := s.ccdGlobal(ctx)
	if err != nil {
		return v, err
	}
	v.VPN = g
	v.DynamicRange, v.StaticRange, err = ccd.Ranges(g.Network)
	if err != nil {
		return v, err
	}
	var data string
	var revision, published, publishedVPN int64
	err = s.Store.DB.QueryRowContext(ctx, "SELECT configuration,revision,published_revision,published_vpn_revision,publication_error FROM device_ccd WHERE device_id=?", deviceID).Scan(&data, &revision, &published, &publishedVPN, &v.PublicationError)
	if errors.Is(err, sql.ErrNoRows) {
		v.Published = true
		return v, nil
	}
	if err != nil {
		return v, err
	}
	if err = json.Unmarshal([]byte(data), &v.Settings); err != nil {
		return v, err
	}
	v.Settings.Revision = revision
	v.Published = revision == published && publishedVPN == g.Revision && v.PublicationError == ""
	return v, nil
}

// ValidateCCDNetwork is called while Store.ConfigurationMu is held, before the
// global settings transaction, so no address can be reserved against an old subnet.
func (s *Service) ValidateCCDNetwork(ctx context.Context, network string) error {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT x.configuration,d.name FROM device_ccd x JOIN devices d ON d.id=x.device_id JOIN clients c ON c.id=d.client_id WHERE d.deleted_at IS NULL AND c.deleted_at IS NULL `)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data, name string
		if err := rows.Scan(&data, &name); err != nil {
			return err
		}
		var value ccd.Settings
		if err := json.Unmarshal([]byte(data), &value); err != nil {
			return err
		}
		if err := ccd.Validate(&value, network); err != nil {
			return problem(409, fmt.Sprintf("Новая подсеть несовместима с постоянным IP устройства «%s». Сначала измените или сбросьте его IP.", name))
		}
	}
	return rows.Err()
}

func (s *Service) SaveDeviceCCD(ctx context.Context, deviceID string, input ccd.Settings, vpnRevision int64, actor string) (CCDView, error) {
	s.Store.ConfigurationMu.Lock()
	defer s.Store.ConfigurationMu.Unlock()
	if s.CCDDir == "" {
		return CCDView{}, problem(503, "Каталог CCD не настроен")
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return CCDView{}, err
	}
	defer unlock()
	current, err := s.DeviceCCD(ctx, deviceID)
	if err != nil {
		return CCDView{}, err
	}
	if current.Settings.Revision != input.Revision || current.VPN.Revision != vpnRevision {
		return CCDView{}, problem(409, "Настройки изменились. Заново откройте редактор перед сохранением.")
	}
	if input.StaticIP == "" && (input.AccessMode == "restricted" || len(input.SiteNetworks) > 0) {
		input.StaticIP = current.Settings.StaticIP
	}
	if input.StaticIP == "" && (input.AccessMode == "restricted" || len(input.SiteNetworks) > 0) {
		ip, err := s.allocatePolicyIP(ctx, deviceID, current.VPN.Network)
		if err != nil {
			return CCDView{}, err
		}
		input.StaticIP = ip
	}
	if err := ccd.Validate(&input, current.VPN.Network); err != nil {
		return CCDView{}, problem(400, err.Error())
	}
	if err := s.validateSiteAssignments(ctx, deviceID, input, current.VPN); err != nil {
		return CCDView{}, problem(409, err.Error())
	}
	var busy int
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT count(*) FROM operations o WHERE o.state IN ('pending','running','partial') AND (o.device_id=? OR (o.kind IN ('delete_client','revoke_client') AND o.client_id=(SELECT client_id FROM devices WHERE id=?)))`, deviceID, deviceID).Scan(&busy); err != nil {
		return CCDView{}, err
	}
	if busy > 0 {
		return CCDView{}, problem(409, "Сначала завершите операцию с сертификатами устройства")
	}
	if input.StaticIP != "" {
		var count int
		if err := s.Store.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM device_ccd WHERE static_ip=? AND device_id!=?)+(SELECT count(*) FROM device_ccd_retired_ips WHERE ip=? AND device_id!=?)`, input.StaticIP, deviceID, input.StaticIP, deviceID).Scan(&count); err != nil {
			return CCDView{}, err
		}
		if count > 0 {
			return CCDView{}, problem(409, "Этот VPN-IP закреплён за другим устройством или ещё используется его прежним подключением")
		}
	}
	input.Revision++
	data, err := json.Marshal(input)
	if err != nil {
		return CCDView{}, err
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return CCDView{}, err
	}
	defer tx.Rollback()
	if current.Settings.StaticIP != "" && current.Settings.StaticIP != input.StaticIP {
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_ccd_retired_ips(ip,device_id,release_after) VALUES (?,?,?) ON CONFLICT(ip) DO UPDATE SET release_after=excluded.release_after`, current.Settings.StaticIP, deviceID, time.Now().Add(2*time.Minute).Unix()); err != nil {
			return CCDView{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM device_ccd_retired_ips WHERE device_id=? AND ip=?", deviceID, input.StaticIP); err != nil {
		return CCDView{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO device_ccd(device_id,configuration,static_ip,revision,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET configuration=excluded.configuration,static_ip=excluded.static_ip,revision=excluded.revision,publication_error='',updated_at=excluded.updated_at`, deviceID, string(data), input.StaticIP, input.Revision, time.Now().Unix()); err != nil {
		return CCDView{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,'device.ccd.update',?,?)", actor, deviceID, time.Now().Unix()); err != nil {
		return CCDView{}, err
	}
	if err := tx.Commit(); err != nil {
		return CCDView{}, err
	}
	defer s.notify("devices", "audit", "settings")
	if err := s.publishCCDLocked(ctx); err != nil {
		return CCDView{}, problem(503, "Настройки сохранены, но публикация CCD не завершена. Повторная попытка выполняется автоматически.")
	}
	return s.DeviceCCD(ctx, deviceID)
}

func (s *Service) PublishCCD(ctx context.Context) error {
	if s.CCDDir == "" {
		return nil
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.publishCCDLocked(ctx)
}

func (s *Service) publishCCDLocked(ctx context.Context) (result error) {
	defer func() {
		if s.PublishAuth != nil {
			if err := s.PublishAuth(ctx); err != nil && result == nil {
				result = err
			}
		}
	}()
	if s.CCDDir == "" {
		return nil
	}
	defer func() {
		// A failed filesystem write must remain visible and retryable after restart.
		message := ""
		if result != nil {
			message = result.Error()
		}
		saveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		changed, err := s.Store.DB.ExecContext(saveCtx, `UPDATE device_ccd SET publication_error=? WHERE publication_error!=? AND device_id IN (SELECT id FROM devices WHERE deleted_at IS NULL)`, message, message)
		if err == nil {
			if n, _ := changed.RowsAffected(); n > 0 {
				s.notify("devices")
			}
		}
	}()
	g, err := s.ccdGlobal(ctx)
	if err != nil {
		return err
	}
	policy, err := s.NetworkPolicy(ctx, g)
	if err != nil {
		return err
	}
	if g.SiteToSite {
		for _, d := range policy.Devices {
			g.SiteNetworks = append(g.SiteNetworks, d.Sites...)
		}
	}
	if err := os.MkdirAll(s.CCDDir, 0700); err != nil {
		return err
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT c.common_name,COALESCE(x.configuration,'{}') FROM devices d JOIN clients u ON u.id=d.client_id JOIN certificates c ON c.device_id=d.id LEFT JOIN device_ccd x ON x.device_id=d.id WHERE d.deleted_at IS NULL AND u.deleted_at IS NULL AND c.status='valid' AND c.not_after>?`, time.Now().Unix())
	if err != nil {
		return err
	}
	wanted := map[string][]byte{}
	for rows.Next() {
		var cn, data string
		if err := rows.Scan(&cn, &data); err != nil {
			rows.Close()
			return err
		}
		if !management.ValidCN(cn) {
			rows.Close()
			return fmt.Errorf("invalid managed CCD certificate name")
		}
		value := ccd.Defaults()
		if err := json.Unmarshal([]byte(data), &value); err != nil {
			rows.Close()
			return err
		}
		body, err := ccd.Render(value, g)
		if err != nil {
			rows.Close()
			return err
		}
		if len(body) > 0 {
			wanted[cn] = body
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for cn, body := range wanted {
		path := filepath.Join(s.CCDDir, cn)
		info, err := os.Lstat(path)
		if err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("CCD %s is not a regular file", cn)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		previous, err := os.ReadFile(path)
		if err == nil {
			if !ccd.IsManaged(string(previous)) {
				return fmt.Errorf("CCD %s was edited manually; preserve it before enabling the editor", cn)
			}
			if bytes.Equal(previous, body) {
				continue
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := atomicWrite(path, body); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(s.CCDDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		// Keep unrelated/manual CCD files; the header identifies files we own.
		if !management.ValidCN(entry.Name()) || wanted[entry.Name()] != nil || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(s.CCDDir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if ccd.IsManaged(string(body)) {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	dir, err := os.Open(s.CCDDir)
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	if s.RuntimeDir != "" {
		body, err := json.Marshal(policy)
		if err != nil {
			return err
		}
		path := filepath.Join(s.RuntimeDir, "network.json")
		old, _ := os.ReadFile(path)
		if !bytes.Equal(old, body) {
			if err := atomicWrite(path, body); err != nil {
				return err
			}
			s.notify("settings")
		}
	}
	changed, err := s.Store.DB.ExecContext(ctx, `UPDATE device_ccd SET published_revision=revision,published_vpn_revision=? WHERE (published_revision!=revision OR published_vpn_revision!=?) AND device_id IN (SELECT id FROM devices WHERE deleted_at IS NULL)`, g.Revision, g.Revision)
	if err == nil {
		if n, _ := changed.RowsAffected(); n > 0 {
			s.notify("devices")
		}
	}
	if err != nil {
		return err
	}
	return s.releaseUnusedCCDAddresses(ctx)
}

func (s *Service) releaseUnusedCCDAddresses(ctx context.Context) error {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT ip FROM device_ccd_retired_ips WHERE release_after<=?", time.Now().Unix())
	if err != nil {
		return err
	}
	addresses := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return err
		}
		addresses = append(addresses, ip)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(addresses) == 0 {
		return err
	}
	// Retain reservations while management is unavailable. Release only after
	// publication, a handshake grace period and a confirmed absence from status.
	if s.Management == nil {
		return nil
	}
	connections, err := s.Management.Status(ctx)
	if err != nil {
		return nil
	}
	active := map[string]bool{}
	for _, connection := range connections {
		active[connection.VirtualAddress] = true
	}
	for _, ip := range addresses {
		if !active[ip] {
			if _, err := s.Store.DB.ExecContext(ctx, "DELETE FROM device_ccd_retired_ips WHERE ip=?", ip); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) allocatePolicyIP(ctx context.Context, deviceID, network string) (string, error) {
	_, fixed, err := ccd.Ranges(network)
	if err != nil {
		return "", err
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT static_ip FROM device_ccd WHERE static_ip!='' AND device_id!=? UNION SELECT ip FROM device_ccd_retired_ips WHERE device_id!=?`, deviceID, deviceID)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return "", err
		}
		used[ip] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	end := netip.MustParseAddr(fixed.End)
	for ip := netip.MustParseAddr(fixed.Start); ip.IsValid() && ip.Compare(end) <= 0; ip = ip.Next() {
		if !used[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", problem(409, "No fixed VPN addresses are available for network policies")
}

func (s *Service) NetworkDevices(ctx context.Context) ([]networkpolicy.Device, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT d.id,d.name,u.name,COALESCE(x.configuration,'{}'),COALESCE(GROUP_CONCAT(DISTINCT CASE WHEN c.status='valid' AND c.not_after>? AND u.disabled=0 THEN c.common_name END),'') FROM devices d JOIN clients u ON u.id=d.client_id LEFT JOIN device_ccd x ON x.device_id=d.id LEFT JOIN certificates c ON c.device_id=d.id WHERE d.deleted_at IS NULL AND u.deleted_at IS NULL GROUP BY d.id ORDER BY d.id`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []networkpolicy.Device{}
	for rows.Next() {
		var d networkpolicy.Device
		var data, names string
		if err := rows.Scan(&d.ID, &d.Name, &d.ClientName, &data, &names); err != nil {
			return nil, err
		}
		value := ccd.Defaults()
		if err := json.Unmarshal([]byte(data), &value); err != nil {
			return nil, err
		}
		d.IP, d.Access, d.Allowed, d.Sites = value.StaticIP, value.AccessMode, value.AllowedNetworks, value.SiteNetworks
		d.DNS = value.DNS
		if value.DNSMode != "custom" {
			d.DNS = nil
		}
		d.CNs = []string{}
		if names != "" {
			d.CNs = strings.Split(names, ",")
		}
		result = append(result, d)
	}
	return result, rows.Err()
}
func (s *Service) NetworkPolicy(ctx context.Context, g ccd.Global) (networkpolicy.Policy, error) {
	p := networkpolicy.Policy{Revision: g.Revision, Network: g.Network, Isolate: g.IsolateClients, SiteToSite: g.SiteToSite, SiteNAT: g.SiteNAT, Devices: []networkpolicy.Device{}}
	devices, err := s.NetworkDevices(ctx)
	if err != nil {
		return p, err
	}
	for _, d := range devices {
		if d.IP != "" || d.Access == "restricted" || len(d.Sites) > 0 {
			if d.DNS == nil {
				d.DNS = g.DNS
			}
			p.Devices = append(p.Devices, d)
		}
	}
	return p, p.Validate()
}
func (s *Service) validateSiteAssignments(ctx context.Context, id string, input ccd.Settings, g ccd.Global) error {
	devices, err := s.NetworkDevices(ctx)
	if err != nil {
		return err
	}
	p := networkpolicy.Policy{Revision: g.Revision, Network: g.Network}
	for _, d := range devices {
		if d.ID == id {
			d.IP, d.Access, d.Allowed, d.Sites = input.StaticIP, input.AccessMode, input.AllowedNetworks, input.SiteNetworks
		}
		p.Devices = append(p.Devices, d)
	}
	return p.Validate()
}
