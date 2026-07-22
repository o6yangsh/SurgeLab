# SurgeLab

SurgeLab is a Windows desktop proxy configuration lab built with Electron and powered by `sing-box` 1.13.14. It imports common share links, compiles them to the current sing-box schema, and provides editable split-routing rules with a local preview.

## Features
- **Local Controller**: The controller strictly binds to `127.0.0.1` and avoids exposing any LAN API.
- **Windows System Proxy**: System mode snapshots the current WinINet proxy, points Windows at the local mixed inbound, restores settings on stop/exit, and recovers stale settings on the next launch after an interrupted session.
- **Profile Management**: Import `ss://`, `trojan://`, `vmess://`, `vless://`, `hy2://`, and `hysteria2://` URIs, including TLS, REALITY, WebSocket, HTTP, HTTPUpgrade, gRPC, QUIC, Shadowsocks plugins, and Hysteria2 obfuscation/bandwidth options.
- **Rule Engine**: Add, reorder, delete, and persist domain, CIDR, process, reject, direct, proxy, and remote rule-set rules. Preview locally decidable rules before starting.
- **DNS Settings**: Supports local, remote (DoH/DoT), and Fake-IP configuration.
- **Modern sing-box config**: Uses typed DNS servers, TUN `address`, route actions, selector/URLTest groups, and remote binary rule sets. The core runs `sing-box check` before every start.
- **Premium Aesthetics**: Dark mode, glassmorphism, and smooth micro-interactions.
- **Diagnostics**: TCP node latency, DNS resolution, and WebRTC ICE-address leak checks.

## Architecture
See `docs/architecture.md` for a detailed breakdown of the application architecture, processes, and security constraints.

## Running the App
Since this is an Electron application:
1. Ensure Node.js and npm are installed.
2. Run `npm ci` to install dependencies.
3. Run `npm start` to launch the application.

Development mode expects a compatible `sing-box` binary in the project root (`sing-box.exe` on Windows). Packaged Windows builds download and verify 1.13.14 in GitHub Actions.

*Note*: If you are testing the UI in a browser without Electron, simply open `src/index.html`. Mock IPC handles are included for visual prototyping.

## Testing
Run `npm test` for the unit tests, or `npm run test:report` to recalculate coverage and regenerate `test-report.md` from Jest's machine-readable output. The report is not maintained by hand.
