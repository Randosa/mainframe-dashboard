# mainframe-dashboard

**MAINFRAME** is a self-hosted Docker application with a WebTUI dashboard for monitoring and recovering services on multiple PCs. The intended deployment is the Debian ZimaBlade. Remote Windows PCs use password-based SSH; Linux PCs support Docker container management.

## What is included

- Overview, incident history and settings screens; responsive layout with horizontally scrollable service tables on small screens.
- Multiple PCs, independent SSH credentials, host fingerprint verification and target discovery.
- Container and Windows-service state checks, plus optional HTTP(S) or TCP checks from the monitoring machine.
- Targeted automatic restarts after repeated failures, dependency ordering, cooldowns and a persistent attempt budget.
- Start, Stop and Restart controls. Stop persists an intentional pause before issuing the remote command. A failed stop keeps recovery paused and records the failure. Start or Restart re-enables the desired running state.
- Docker Desktop restart requires an explicit one-time approval in the dashboard. Network failure never automatically restarts Docker.
- SSH and Docker outages, repair attempts and verified recoveries appear in incident history.
- AES-256-GCM encryption of stored SSH passwords; dashboard password hashing with scrypt; password-only SSH authentication.
- SQLite persistence, 24-hour duration-weighted availability, 30-day samples and 90-day resolved incident retention.

The seven example names—Caddy, Immich, Homepage, Minecraft, Crafty, playit and Tailscale—are initially listed under `Windows PC`. They are **unconfigured**, not represented as healthy. Set the actual SSH address and container/service targets in Settings. No SSH connections occur until host monitoring is enabled, credentials saved and the server fingerprint trusted. Automatic recovery is off until enabled per service.

## Deploy on the ZimaBlade

### Docker run

Build the image from this repository, then run it with persistent data and credential-key volumes:

```bash
git clone https://github.com/Randosa/mainframe-dashboard.git
cd mainframe-dashboard
docker build -t mainframe-dashboard:latest .

docker run -d \
  --name mainframe-dashboard \
  --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  -v mainframe-data:/data \
  -v mainframe-secrets:/secrets \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  mainframe-dashboard:latest
```

This command uses a **locally built image**; no prebuilt registry image is currently published. Complete initial password setup through `http://127.0.0.1:3000` or an SSH tunnel before exposing the dashboard to other devices. For LAN or Tailscale access, replace `127.0.0.1` in the port mapping with the monitoring machine's address. Use private HTTPS or an SSH tunnel when entering credentials across an untrusted LAN.

Both named volumes must be preserved when replacing the container. Removing the container alone leaves them intact. The application does not need a mounted Docker socket: it manages the selected PCs through SSH.

### Docker Compose

1. Copy this project directory to the ZimaBlade with Docker Engine and Docker Compose installed.
2. Copy `.env.example` to `.env`. Initially leave `MAINFRAME_BIND_IP=127.0.0.1`.
3. Run `docker compose up -d --build` in this directory.
4. Reach the initial setup privately, for example with an SSH tunnel: `ssh -L 3000:127.0.0.1:3000 USER@ZIMABLADE`. Open `http://127.0.0.1:3000` and set a dashboard password of at least 12 characters.
5. Set `MAINFRAME_BIND_IP` to the ZimaBlade's LAN **or** Tailscale address, then run `docker compose up -d` again. To bind all interfaces for access from both networks, use `0.0.0.0` and restrict access with the host firewall. No public exposure is configured by this project.
6. For HTTPS behind an existing private reverse proxy, set `COOKIE_SECURE=true`. Plain HTTP does not encrypt the browser-to-dashboard connection; SSH transport itself is encrypted. Use private HTTPS or an SSH tunnel when entering credentials across an untrusted LAN.
7. In Settings, edit the desktop, enter its SSH username/password, verify the host fingerprint, and use **Discover targets**. Never put passwords in chat, Compose files or command arguments.
8. Configure the actual target for each service and an application check where possible. Enable host monitoring, inspect results, then enable each desired recovery rule.

For a Windows OpenSSH server, compare the fingerprint with `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub` (or the negotiated host key's matching public file). The dashboard's fingerprint is the server identity, not a login key or token. A changed host address clears its trusted fingerprint. Changed host keys require a fresh probe and explicit confirmation.

## Credentials and backups

The `/data` volume holds the database. SSH passwords are encrypted there. `/secrets/vault.key` holds a randomly generated **32-byte binary encryption key**, created with owner-only permissions under the non-root application user. No SSH private login key or plain-text SSH password file is used. The separate secrets volume allows unattended unlocking after restart.

Binary encoding is not encryption: a person who obtains both the database and vault key can decrypt the passwords. This version relies on host permissions and separate volumes, not TPM binding or an operating-system credential store. It does not claim to protect secrets from an administrator who controls the running host. Back up the database and original key to a protected location, keeping key access separate. Losing the original key makes saved SSH passwords unrecoverable; the app refuses to silently create a replacement.

Stop the application before copying the SQLite database and its companion files, or use a SQLite backup tool. Preserve **both named volumes** when moving machines or updating. `docker compose down` preserves them; `docker compose down -v` deletes configuration, history and the encryption key. Sessions intentionally expire on application restart.

## Recovery rules

Default suggested limits are 3 failed checks, 3 restart attempts and a 120-second cooldown; these are editable per service. An automatic restart is not counted as successful until a later check passes. Ten minutes of stable availability resets the attempt budget. Exhausted budgets require manual attention, or a manual Start/Restart. A dependency must be online before a dependent target can be repaired; cycles are refused.

Checks occur every 30 seconds. Recovery and manual actions on the same PC are serialized. Busy actions return a message to retry rather than race each other. An unavailable SSH connection gives **unknown** service state. An unavailable Docker engine also gives unknown container state and presents **Review Docker restart**. Containers are not restarted solely because their PC became unreachable.

Dashboard Stop is authoritative. Stops performed outside this dashboard are not reliably distinguishable from crashes: a configured, desired-running target may be restarted. Use the dashboard Stop or disable automatic recovery before external maintenance. A paused service is excluded from uptime, as are unknown periods and monitoring gaps longer than 90 seconds. Uptime includes only observed online/offline durations; the accompanying observed percentage shows how much of the 24-hour window is covered. A new installation does not claim a full day of uptime.

For reverse-proxied applications, use Caddy as a dependency **only for checks through Caddy**. A stopped dependency pauses dependent recovery. Immich and other Compose applications may contain several containers; add their components separately with their actual names and dependencies. This version does not restart whole Compose stacks as one action.

## Windows and Docker Desktop

Windows services are background programs managed by Windows Service Control Manager. Use the discovered **service name**, not a guessed display name. The SSH account must have permission to inspect Docker and to manage any selected Windows service. The application does not grant privileges or elevate automatically.

Docker Desktop is often tied to an interactive Windows user session. Its CLI must be available to the SSH account. Approved Docker recovery calls `docker desktop restart`; installed version and session behavior must be verified on the actual PC. A command failure is recorded instead of attempting a reboot, resetting WSL, or killing arbitrary processes. The local Docker deployment test does **not** establish that remote Docker Desktop recovery works in that account's SSH session.

Tailscale repair defaults to approval required because stopping/restarting the connection being used for SSH can interrupt management. Prefer a direct LAN SSH address when available. Tailscale's current installation type must be discovered; it is not presumed to be a container. Ordinary desktop GUI applications and automatic PC reboots are outside this version. No persistent Windows helper is installed.

## Local development and preview

Requires Node.js 24 and pnpm 11.25.0:

```text
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
pnpm start
```

`pnpm preview` serves read-only sample data. For an occupied port, set `PORT` to another value (for example 4318). Set `HOST=127.0.0.1` for a local-only development server. Preview mode refuses all writes and never starts the monitoring worker. Its database and key use separate `data/demo` and `secrets/demo.key` paths by default.

## Reused open-source components

- [WebTUI](https://webtui.ironclad.sh/) 0.1.10: local modular CSS; no runtime CDN dependency.
- [ssh2](https://github.com/mscdex/ssh2) 1.17.0: SSH transport, password authentication and server identity checking.
- Node.js built-in SQLite and cryptography: persistence and established encryption/hashing primitives.
- Docker's own CLI: container inspection and bounded target actions; Docker Desktop's supported CLI for approved engine restart.

Uptime Kuma and Autoheal were considered. Their full applications are not embedded in this release: maintaining a unified multi-PC configuration, manual-stop intent, approval flow and incident timeline calls for coordination they do not directly provide together. Mainframe's custom code supplies that coordination while relying on established transport, storage, styling and cryptography components.

## Validation

`node --test` covers encrypted vault persistence/tamper rejection, missing key handling, password hashing, recovery thresholds/budgets, manual stops, dependency ordering, multi-PC isolation, monitoring gaps, command target validation, password-based SSH against an isolated SSH fixture, API authentication/CSRF, multi-PC configuration persistence and read-only preview restrictions.

Live target repairs require actual SSH credentials entered by the owner through the dashboard and a controlled failure test. They have not been performed during initial development.
