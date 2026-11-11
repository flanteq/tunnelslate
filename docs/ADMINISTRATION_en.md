# Administering TunnelSlate

English · [Русский](/docs/ADMINISTRATION_ru.md) · [Quickstart](/docs/QUICKSTART_en.md) · [Overview](/docs/OVERVIEW_en.md)

## .env reference

Edit `.env`, then run `docker compose up -d` to apply changes.

| Setting | What to enter |
| --- | --- |
| `TUNNELSLATE_PUBLIC_URL` | The panel address, including the scheme and any port, without a path after the hostname. It must match the address you open in the browser. |
| `TUNNELSLATE_BASE_PATH` | Leave empty for a dedicated domain. For `https://control.example.com/ovpn/`, enter `/ovpn` here and only `https://control.example.com` in `PUBLIC_URL`. |
| `TUNNELSLATE_COOKIE_SECURE` | `true` for HTTPS; `false` for local HTTP access. |
| `TUNNELSLATE_SESSION_TTL` | How long a panel sign-in remains valid. Default: `12h`; allowed range: `1m` to `168h`. |
| `TUNNELSLATE_AUDIT_RETENTION_DAYS` | Activity log retention in days. Default: `365`; allowed range: `1` to `36500`. Older events are removed automatically. |
| `TUNNELSLATE_STATS_RETENTION_DAYS` | Detailed VPN statistics retention in days. Default: `90`; allowed range: `1` to `36500`. Lifetime device, client and server totals are kept. |
| `TUNNELSLATE_TRUSTED_PROXIES` | Optional comma-separated addresses of your reverse proxies. Used for session IPs and sign-in brute-force protection behind nginx. Without it, the direct connection address is used, so users behind the same proxy share a limit. |

## Data directories

The Compose example uses `./data/app`, `./data/pki`, `./data/openvpn`, `./data/ccd` and `./data/control`. To move them, change only the host paths on the left in `volumes`; keep the container paths from the example. Include these directories, `.env` and `docker-compose.yml` in backups.

## Panel access

### nginx and URL base paths

Host nginx forwards requests to `http://127.0.0.1:8090`. If you change the panel port in Compose, update nginx as well.

Use the [dedicated domain configuration](/deploy/nginx.conf.example) or the [/ovpn path configuration](/deploy/nginx.subpath.conf.example). Replace the domain and certificate paths, keeping the event streaming and forwarded header settings from the example.

For `https://control.example.com/ovpn/`, set:

```dotenv
TUNNELSLATE_PUBLIC_URL=https://control.example.com
TUNNELSLATE_BASE_PATH=/ovpn
TUNNELSLATE_COOKIE_SECURE=true
```

nginx must preserve the full `/ovpn/` path. Check the configuration with `nginx -t` and reload nginx.

### Client IPs behind nginx

Set `TUNNELSLATE_TRUSTED_PROXIES` to the nginx address seen by the application. With host nginx, this is usually the Docker gateway:

```sh
docker inspect tunnelslate --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}'
```

Run `docker compose up -d` after editing `.env`. Forwarded IPs are accepted only from trusted proxies; specify their actual addresses or necessary ranges.

### Local check without nginx

Set these values in `.env`:

```dotenv
TUNNELSLATE_PUBLIC_URL=http://localhost:8090
TUNNELSLATE_BASE_PATH=
TUNNELSLATE_COOKIE_SECURE=false
```

Run `docker compose up -d` and open `http://localhost:8090` on the server. To connect from another computer, run this command on that computer:

```sh
ssh -N -L 8090:127.0.0.1:8090 user@server
```

Replace `user@server` with your credentials and open `http://localhost:8090` in that computer's browser.

## Accounts and profiles

Create additional administrators in **Accounts**. Each receives a one-time password for first sign-in. The built-in `admin` can be renamed or replaced with another account.

The first account's password is stored at `/data/app/initial_admin_password` inside the panel container, or `./data/app/initial_admin_password` on the host with default paths. Setting a permanent password removes the file. Restarting the container does not reset the password.

To let a client download profiles themselves, create a link in their card. Copy it before closing the dialog: it is shown only once. Treat it like a password.

## Sign-in brute-force protection

Protection is enabled automatically. Five incorrect passwords or TOTP codes from one IP within the last 15 minutes block new sign-ins from that address for 15 minutes, starting with the fifth failure. Attempts across different usernames count together. Successful sign-ins neither add failures nor erase earlier ones. Requests during a ban do not extend it.

The panel shows how long to wait. Bans survive container restarts and expire automatically. Expired failures and bans are removed. Each new ban creates one **WARNING** activity event with the IP address; subsequent blocked requests do not create separate events.

Only new sign-ins from that IP are blocked, including completion of TOTP sign-in. Existing administrator sessions, VPN connections, and client links continue to work. An administrator can sign in from another address. Changing or resetting a password does not remove an IP ban.

Behind nginx, configure `TUNNELSLATE_TRUSTED_PROXIES` so limits use client addresses. The application accepts forwarded IPs only from trusted proxies. Specify their actual addresses or necessary ranges rather than trusting all addresses. Administrators behind the same office NAT share a limit.

A separate request limit protects the application from load: up to 60 requests per 5 minutes from one IP across sign-in and TOTP verification, including successful and malformed requests. Exceeding it also produces a temporary refusal. TOTP additionally retains its own per-account attempt limit.

## Two-factor sign-in with TOTP

TOTP is disabled by default. Each administrator can set it up for their own account:

1. Open **Accounts** and click **Set up TOTP** next to your name.
2. Enter your current password. Scan the QR code with an authenticator app or enter the key manually.
3. Enter the app's six-digit code and click **Enable TOTP**.

The second factor stays disabled until the code is confirmed. Finish setup within 10 minutes. Enabling it ends your other account sessions while keeping the current one open.

On subsequent sign-ins, enter your password first, then an authenticator code. Complete verification within five minutes. Codes change every 30 seconds and can only be accepted once. If a code has already been used, wait for the next one. Keep the time on your phone and server accurate.

To turn it off, click **Disable TOTP** next to your account and confirm with your current password and code. Your other account sessions will end. Other administrators' settings are unaffected.

The TOTP encryption key is created automatically at `data/app/totp.key`. It is already inside the persistent data directory; back it up with the database. Restoring only the database without this file is not enough to verify codes.

## If an administrator's password is lost

You can restore access from the server's terminal even if nobody can sign in to the panel. The panel container must be running. You do not need to delete data or restart the VPN.

To reset an existing account's password, replace `username` with its name:

```sh
docker exec -it tunnelslate reset-password username
```

Or create a new administrator:

```sh
docker exec -it tunnelslate create-admin new-admin
```

The command prints the account name and a new one-time password directly in the terminal. Use them to sign in and choose a permanent password. Other sections remain locked until then. If you close the page, the one-time password remains valid.

A reset immediately invalidates the old password and ends all sessions for that account. Other administrators stay signed in. Creating an account whose name is already taken, or resetting a missing account, returns a clear error without changing anything. Names are case-insensitive. New names must contain 3–64 Latin letters, digits, dots, hyphens, or underscores and start with a letter or digit. The name `system` is reserved.

The password is not written to logs or to the initial password file. Save the command output and share it securely with the account owner. If you lose the output, run a reset again. The operations themselves appear in the activity log with the actor `system:console`.

### If access to the authenticator app is lost

A password reset preserves TOTP. To separately disable a lost second factor, run:

```sh
docker exec -it tunnelslate reset-totp username
```

This ends all sessions for the account and keeps its password unchanged. Sign in with that password and set up TOTP again. If both the password and authenticator are lost, run both `reset-totp` and `reset-password`. The TOTP reset is also recorded in the activity log with the actor `system:console`.

## Later changes and updates

Change VPN settings in the panel. The [OpenVPN settings guide](/docs/OPENVPN_SETTINGS_en.md) explains every field and per-device option, with isolation and site-to-site examples.

Applying shared settings restarts OpenVPN and interrupts connections. After changing the public address, port, protocol, MTU, or MSS, download and reimport profiles; DNS and route changes usually only require reconnection.

### Moving from a test installation made before the first release

The first release creates its database from one initial schema. Databases from earlier test builds are incompatible: the application reports a clear startup error and does not recreate them automatically.

If you used one of those test builds, keep its data separately and start with empty data directories. With the default example paths:

```sh
docker compose down
mv data data.pre-release-backup
docker compose up -d
```

Choose an unused backup directory name. If you changed the `volumes` paths, preserve and replace all five directories with empty ones: `app`, `pki`, `openvpn`, `ccd` and `control`. Keep `.env` and `docker-compose.yml`. Deleting only the SQLite file does not make a clean installation.

Then repeat sign-in and VPN setup using [quickstart steps 4–5](/docs/QUICKSTART_en.md#4-sign-in). Accounts, settings, clients and statistics from the old test installation are not transferred; the new PKI requires new `.ovpn` profiles.

### Updating the application and preserving data

After editing `.env` or Compose, run `docker compose up -d` again.

To update a Git checkout:

```sh
git pull --ff-only
docker compose up -d
```

Before updating a compatible release, back up your data. Keep your own `.env`, `docker-compose.yml`, and data directories. If the Compose or nginx examples change, copy the relevant changes into your local settings. For an archive installation, replace the source files with the new distribution and run the same startup command.

Backups should include all data directories and your local settings. Restore the database and certificates from the same consistent backup, preserving file permissions. When copying SQLite files, stopping the application is the simplest safe option. Backing up a running database requires a method that accounts for its write-ahead log. There is no separate backup container.

Deleting the data makes the next start a new installation with a new administrator and certificates. Existing profiles will not connect to that new installation.

## Installing DCO on the host

DCO accelerates VPN traffic processing through the host kernel. The default **Automatic** mode uses regular processing when the driver or configuration is incompatible. The panel shows actual DCO status in the server overview and Connection and DNS settings. **Off** explicitly disables acceleration.

OpenVPN 2.7 needs the `ovpn` module on the Docker host for DCO. It is included in upstream Linux from 6.16 when enabled in the kernel build; [ovpn-backports](https://github.com/OpenVPN/ovpn-backports) supports older kernels. Installing a package inside the container is not enough. The application does not install or load host modules; prepare them separately. Changing DCO, connection limits, or keepalive does not require downloading profiles again.

This step is optional: the VPN works without the driver. OpenVPN 2.7 needs `ovpn`; the older `ovpn-dco` driver is for OpenVPN 2.6.

If your kernel already includes the driver, load it:

```sh
sudo modprobe ovpn
```

If the module is missing, install a backport for your distribution. The following example covers Rocky Linux 9 and compatible systems with a regular kernel. For other systems, follow the [OpenVPN instructions](https://community.openvpn.net/Pages/OpenVPN%20software%20repos).

```sh
sudo dnf install epel-release dnf-plugins-core
sudo dnf copr enable @OpenVPN/openvpn-release-2.7
sudo dnf install --setopt=install_weak_deps=False \
  "kernel-devel-$(uname -r)" \
  "kernel-devel-matched-$(uname -r)" \
  kmod-ovpn
```

Despite its name, this `kmod-ovpn` package uses DKMS to build the driver for the host kernel. Both `kernel-devel` and `kernel-devel-matched` must match `uname -r`. Review the transaction before confirming: preparing a driver for the running kernel does not require installing a new kernel.

If the exact package versions are no longer in the current repository, find them in your distribution's official archive. For Rocky, use [Rocky Linux Vault](https://download.rockylinux.org/vault/rocky/): packages are under `AppStream/<architecture>/os/Packages/k/` for the corresponding release. Download both RPMs for the running kernel and install them with the driver from the download directory:

```sh
sudo dnf install --setopt=install_weak_deps=False --setopt=localpkg_gpgcheck=True \
  "./kernel-devel-$(uname -r).rpm" \
  "./kernel-devel-matched-$(uname -r).rpm" \
  kmod-ovpn
```

Check the build and load the module:

```sh
sudo dkms autoinstall -k "$(uname -r)"
dkms status
sudo modprobe ovpn
lsmod | grep '^ovpn'
```

`dkms status` should show `installed` for the running kernel. With Secure Boot enabled, the module also needs a signature from a key trusted by the system; setup depends on your distribution.

To load the tested module when the host starts:

```sh
printf 'ovpn\n' | sudo tee /etc/modules-load.d/ovpn.conf > /dev/null
```

In the panel, choose **Connection and DNS → DCO → Automatic** and apply the settings. If that mode is already selected, restart the VPN container; existing connections will be interrupted:

```sh
docker compose restart tunnelslate-vpn
```

After a few seconds, the panel should report **DCO: Active**. For an additional check:

```sh
docker compose exec tunnelslate-vpn \
  sh -c 'grep dco_enabled /run/openvpn/status.log'
```

A value of `1` means the running OpenVPN daemon is using DCO; `0` means it is not. A `[DCO]` version flag only indicates build support. If the module is loaded but acceleration is inactive, check the reason in the panel and the VPN container logs.

After a kernel update, check that matching `kernel-devel` is available, DKMS built the module successfully, and `ovpn` loads for the new kernel. To stop using acceleration, select DCO **Off** in the panel.

## External VPN authentication

Certificate authentication remains the default. Configure LDAP/RADIUS providers in the panel; they require no `.env` variables. Add an external password check for selected clients and devices. See the [configuration guide and limitations](/docs/VPN_AUTH_en.md).

Providers introduce a `data/app/vpn-auth.key` encryption key. Back it up with the database, just like `totp.key`.

## Panel settings and monitoring

**Panel settings** lets you name the instance and enable Prometheus metrics. The endpoint is disabled by default. mTLS protects scraping with certificates supplied as files or through the panel. [Configure monitoring, Grafana and alerts](/docs/MONITORING_en.md).
