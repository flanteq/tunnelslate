# How TunnelSlate works

English · [Русский](/docs/ARCHITECTURE_ru.md) · [Overview](/docs/OVERVIEW_en.md) · [Quickstart](/docs/QUICKSTART_en.md) · [OpenVPN settings](/docs/OPENVPN_SETTINGS_en.md)

TunnelSlate manages a separate OpenVPN server. The panel handles settings and access; OpenVPN carries the VPN traffic. The VPN does not need an open browser or an active panel tab to work.

## Parts of an installation

| Part | Responsibility |
| --- | --- |
| Browser interface | Shows clients, devices, connections, and settings. Sends administrator actions to the backend. |
| Panel container | Serves the interface, checks permissions, stores settings, manages certificates, and runs background tasks. |
| OpenVPN container | Accepts VPN connections and carries traffic between devices and the networks they can reach. |
| nginx | Provides HTTPS access to the panel. It is configured separately on the host or in your own Docker setup. |
| Host directories | Keep the database, keys, certificates, and working settings independently of the containers. |

The interface uses Vue and the backend uses Go. They ship together in the panel image; there is no separate frontend server. The main installation consists of two containers and needs neither Kubernetes nor an external database server.

## What happens when you use the panel

1. An administrator opens the panel through nginx and signs in.
2. The interface asks the backend for data. Permissions are checked on the server, not only in the browser.
3. When settings change, the backend saves them and prepares files for OpenVPN. Certificate operations use the existing certificate authority.
4. OpenVPN receives the changes through shared directories or a local management socket.
5. The panel sends the browser a change event. The interface fetches the data it needs and updates the relevant parts of the page.

The persistent event connection is called SSE. If it breaks, the browser reconnects; temporarily unavailable data is retried. Open browser tabs share a backend snapshot of OpenVPN's state, rather than each polling the VPN server separately.

## How the panel communicates with OpenVPN

**Files.** The panel and OpenVPN share directories containing configuration, certificates, revocation lists, and per-device settings. The backend publishes prepared files, and the OpenVPN container reads them.

**Management Interface.** A local management socket provides the running OpenVPN version, connection list, and traffic figures. It also lets the panel disconnect individual sessions. The socket lives in a shared control directory and is not exposed to the internet. The panel does not need the Docker socket or the ability to run commands on the host.

Changing general VPN settings restarts the OpenVPN process inside its container and interrupts existing connections. Updating the certificate revocation list does not require that restart. Individual access rules update without restarting the server. VPN IP or site-network changes reconnect only the affected device. Other CCD options and new site-to-site routes are delivered on the next connection.

Parameters are edited in three tabs of one form: basic settings, connection and DNS, and networks and access. Connection and DNS options include DCO, connection limits, keepalive, MTU/MSS, and DNS domains. MTU is included in downloaded profiles; DNS domains are sent on connection. Per-device domains override shared domains independently of DNS servers. The VPN container enforces custom MSS limits in both directions through the kernel, including with DCO; changing modes replaces or removes these rules. The panel obtains actual DCO use from the running OpenVPN daemon in its shared status snapshot. The VPN container separately reports the host kernel version and whether the `ovpn` module is loaded, helping explain why acceleration is not in use. The panel does not install host drivers or treat DCO build support as proof that it is active.

## Clients, devices, and certificates

A client groups the devices belonging to a person or group. Each device receives its own key and certificate. This makes it possible to revoke one device while keeping the client's other connections working.

The backend manages certificates through Easy-RSA. It records an operation's intent before starting, then tracks its completed stages. If the process stops, the application can resume unfinished operations after startup. A shared lock prevents issuance, revocation, and CRL renewal from changing the PKI at the same time.

Reissuing creates a new key and certificate and revokes the device's old certificates. Revoking updates the certificate revocation list, or CRL, and disconnects the affected active sessions. Deletion hides a device or client while retaining certificate and activity history.

An `.ovpn` file is assembled at download time from current settings and the device's certificate. Ready-made profiles are not a separate source of data. After changing an address, port, or protocol, download an updated file; a previously downloaded file does not change by itself.

The visual CCD editor separates address, DNS, routes and network access into four tabs with one save action. It saves per-device settings in the database. The backend turns them into OpenVPN configuration files. Settings belong to the device and survive certificate reissues. Networks behind VPN routers are bound to certificates through CCD. The panel automatically reserves a fixed VPN IP for network policies. The backend publishes validated network configuration; a small helper inside the VPN container applies firewall rules and routes before OpenVPN starts and updates individual policies while it is running. VPN IP or site-network changes disconnect only the affected device through the Management Interface. Source ownership checks prevent peers from claiming another device’s VPN IP or site networks. Policies cover both traffic directions and established connections. The application does not change host rules; external return routes remain the administrator’s responsibility. Routes direct traffic; the VPN container firewall enforces network access. Global isolation takes precedence over individual permissions, including site networks. Remote-network NAT applies to traffic leaving the VPN; traffic between sites preserves source addresses.

## Administrators and client links

Administrators have full access to the panel. First sign-in uses a generated one-time password that must be replaced with a permanent one. Passwords are stored as hashes. Administrators can inspect and end unexpired sessions.

Sign-in failures are tracked by IP: five failures within 15 minutes block new sign-ins from that address for 15 minutes. Failures and ban expiry times live in SQLite, survive restarts, and are automatically cleaned up after expiry. Only trusted proxies can supply a forwarded client address. A new ban is recorded as a warning; existing sessions remain active.

Each administrator can enable TOTP for their own account. Sign-in then requires an authenticator code after the password; no session is created before verification. Used codes cannot be replayed, and verification attempts are limited. Setup and disabling require the password and a code, and end that account's other sessions.

TOTP secrets are encrypted in the database. The encryption key is stored separately at `data/app/totp.key` and must be backed up with the database. If a phone is lost, access can be recovered from the server console. Resetting a password alone preserves the second factor.

VPN clients do not sign in to the admin panel. If an administrator chooses, a client receives a long random link to their profiles. The server stores a hash of its secret. The link grants access only to that client, including profiles issued later.

Replacing or deleting the link closes access through it. Reporting a compromised link also starts revoking all of the client's certificates and records a critical event. An administrator restores access afterwards.

## Where data lives

| Default directory | Contents |
| --- | --- |
| `data/app` | The SQLite database: accounts, sessions, clients, settings, operations, and activity log. It also holds separate encryption keys for TOTP, LDAP/RADIUS service secrets and the metrics private key, and temporarily the first administrator's password. |
| `data/pki` | The certificate authority, keys, certificates, and the record of their states. |
| `data/openvpn` | Configuration, certificates, and CRL prepared for the VPN server. |
| `data/ccd` | Per-device settings published for OpenVPN. |
| `data/control` | The management socket and information about applied settings. The socket is recreated at startup. |

These are bind mounts: ordinary host directories. You can change their locations in Compose. Replacing an image does not remove the data. Restoring an installation requires a consistent copy of the database and PKI.

On first startup, the panel creates the complete database structure. Applied changes are recorded with checksums, so restarting preserves data, while changed migrations or an incompatible build stop startup with an explanation. After the first release, subsequent schema changes will be applied in sequence. Old test databases require a [clean installation](/docs/ADMINISTRATION_en.md#moving-from-a-test-installation-made-before-the-first-release).

## Automatic maintenance

The panel resumes unfinished operations, publishes settings, checks connections whose certificates have expired, and cleans up old sessions. The activity log has a retention limit, set to 365 days by default.

A CRL is issued for 180 days. The application checks whether it needs renewal at startup and once a day afterwards. Renewal starts when 30 days or less remain; after a failure, it retries in five minutes. New files are checked before publication, and previously published revocations must be preserved.

## If the panel is unavailable

Working VPN connections do not depend on a browser tab or nginx. If the panel container stops, OpenVPN continues with the last published settings and certificate checks. However, access management and the panel's background work, including CRL renewal, remain paused until it returns.

Damaged or incomplete PKI is never automatically replaced with a new certificate authority. The application requires the existing data to be repaired or restored, preserving the relationship with issued profiles.

## External VPN providers

A client can use its certificate alone or combine it with a password checked by a specific LDAP/RADIUS provider. Every device uses the provider and username assigned to its client; individual profiles cannot override this policy. The administrator sets the server policy; editing a downloaded profile cannot remove its password requirement. Panel administrator accounts remain separate from VPN providers.

OpenVPN verifies passwords asynchronously through a private local socket, so a slow external service does not block other VPN traffic. Certificates continue to identify devices, preserving CCD, network rules and certificate revocation in every mode. Before a connection completes, its authentication result is checked against the current policy. Changing a policy or provider disconnects affected sessions; pending disconnections survive panel restarts.

Service credentials are encrypted in the database with a separate key in the application data directory. Users’ passwords are used only during verification and are not stored. LDAP requires TLS; RADIUS requires verified response integrity and a protected network between services. See the [LDAP/RADIUS guide](/docs/VPN_AUTH_en.md) for configuration details.

Certificate-only connections use the last published local authentication policy even while the panel is stopped. New and repeat LDAP/RADIUS checks require the panel; they are denied while it is unavailable. Existing VPN tunnels last until their next check or disconnection. The application data directory also contains the VPN provider encryption key, and the shared control directory contains the private authentication socket and published policy.

## Statistics collection

The OpenVPN container saves intermediate and final session counters in a shared persistent directory, even while the panel is stopped. The backend transfers these records into the database, updating session history, daily records and independent device, client and server lifetime totals together. Repeated delivery is safe: previously counted values are not added twice.

Retention removes detailed history while preserving lifetime totals. Deleting a device does not subtract its past usage from client totals; deleting a client does not subtract it from server totals. Certificate reissue preserves the association with the device. See the [statistics guide](/docs/STATISTICS_en.md).

## Monitoring

The panel can optionally open a separate Prometheus endpoint on port 9090. It uses persisted statistics and the shared OpenVPN snapshot, without opening another Management Interface connection for each scrape. The panel itself verifies mTLS; web pages and the API continue to use their existing port. Monitoring settings and certificates are independent of VPN settings. [Monitoring guide](/docs/MONITORING_en.md).
