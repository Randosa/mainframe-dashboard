# Initial verification — 1 October 2026

- 16 automated tests passed: vault encryption/tamper rejection, restart persistence, recovery rules, target validation, dependency ordering, multi-PC isolation, isolated SSH password authentication, API authentication/CSRF and preview write rejection.
- Docker image built successfully with the pinned dependency lockfile.
- Compose configuration validated.
- Read-only preview container became healthy.
- Normal application tested with disposable credentials and no remote hosts enabled. Browser sign-in, additional-PC configuration and HTTP service-check configuration worked.
- The second PC and service survived a container restart.
- Container ran as non-root UID 1000. Vault key permissions verified as 600, owner node, length 32 bytes.
- Desktop and narrow-screen layouts inspected; horizontal overflow remained inside the service table.
- Both temporary test containers, four temporary volumes and test image removed. Local preview process stopped.

No live SSH credentials were used. No real homelab container, Windows service, Docker engine or host was restarted. Remote Docker Desktop recovery under the intended Windows SSH account remains to be verified after configuration on the ZimaBlade.

`dashboard-preview.jpg` shows sample data, not live service health. `settings-test.jpg` shows the disposable second-PC configuration used in the Docker smoke test.
