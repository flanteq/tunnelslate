# Changelog

English · [Русский](/docs/CHANGELOG_ru.md) · [About the project](/docs/OVERVIEW_en.md)

## [Unreleased]

## [0.4.0] - 2026-11-11

### Added

- TunnelSlate branding, `tunnelslate` containers, `TUNNELSLATE_` environment variables and `tunnelslate_` metrics.
- GPL-3.0-or-later license.
- Docker Compose deployment, nginx examples and URL base path support.
- Browser-based OpenVPN configuration and PKI initialization.
- Clients with multiple devices and individual certificates.
- Certificate expiry selection within the CA lifetime; 825 days by default.
- Certificate issuance, reissue, revocation, history and automatic recovery of unfinished operations.
- Current `.ovpn` downloads and private client profile links.
- Client and device deletion with certificate revocation.
- DNS, routing, MTU/MSS, keepalive and connection limit settings.
- Per-device VPN addresses, DNS, routes and network permissions.
- Device isolation and site-to-site with routing or NAT.
- Per-device network policy updates without restarting the server.
- DCO support with automatic mode and status display.
- LDAP with LDAPS/StartTLS and group restrictions; client-wide policies for all devices.
- RADIUS PAP and MFA; configurable timeout of 5–300 seconds, defaulting to 90.
- Live VPN connection monitoring and disconnection.
- Session statistics, server/client/device lifetime totals and daily device history.
- Today and all-time traffic on Overview; detailed statistics retained for 90 days by default.
- Multiple administrators, one-time passwords, password changes and resets, session IPs and termination.
- Recovery commands: `create-admin`, `reset-password`, `reset-totp`.
- Activity log with WARNING/CRITICAL severity and 365-day default retention.
- Automatic CRL renewal with daily checks.
- Client and certificate search, list pagination.
- Custom instance name, Russian and English, light and dark themes.
- Component health, panel/OpenVPN versions and host kernel version.
- Prometheus metrics for traffic, connections, component health, authentication failures and certificate/CRL expiry.
- Separate metrics port 9090, HTTP or mTLS, file or PEM certificates; metrics disabled by default.
- Grafana dashboard, Prometheus scrape examples and alert rules.

### Security

- Administrator TOTP with protection against code reuse.
- A 15-minute IP ban after five password or TOTP failures within 15 minutes.
- Encryption of TOTP and LDAP/RADIUS secrets and the metrics private key.
- External authentication bound to the assigned username; mandatory RADIUS Message-Authenticator.
- Compromised-link reports disable the link, revoke client certificates and create a CRITICAL event.

### Documentation

- RU/EN quickstart and a separate administration guide: `.env`, TOTP, access recovery, updates and backups.
- RU/EN guides for architecture, VPN settings, LDAP/RADIUS, statistics and monitoring.
- Host DCO installation instructions and current interface screenshots.

### Upgrade notes

- One initial database schema with migration checksums. Earlier test builds, including those under previous names, require a [clean installation](/docs/ADMINISTRATION_en.md#moving-from-a-test-installation-made-before-the-first-release).
- Back up all data directories, local configuration and the `totp.key`, `vpn-auth.key`, `metrics.key` files with the database.
