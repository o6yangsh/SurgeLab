# SurgeLab

SurgeLab is a Windows desktop application prototype that acts as a local proxy configuration lab, built with Electron and powered by `sing-box`. It provides a premium, native GUI to manage proxy profiles, configure routing rules, and perform network diagnostics.

## Features
- **Local Controller**: The controller strictly binds to `127.0.0.1` and avoids exposing any LAN API.
- **Profile Management**: Import `ss://`, `trojan://`, `vmess://`, `vless://`, and `hy2://` URIs.
- **Rule Engine**: Preview rule matching before committing.
- **DNS Settings**: Supports local, remote (DoH/DoT), and Fake-IP configuration.
- **Premium Aesthetics**: Dark mode, glassmorphism, and smooth micro-interactions.
- **Diagnostics**: Built-in latency testing, DNS resolution testing, and WebRTC leak warnings.

## Architecture
See `docs/architecture.md` for a detailed breakdown of the application architecture, processes, and security constraints.

## Running the App
Since this is an Electron application:
1. Ensure Node.js and npm are installed.
2. Run `npm install` to install dependencies.
3. Run `npm start` to launch the application.

*Note*: If you are testing the UI in a browser without Electron, simply open `src/index.html`. Mock IPC handles are included for visual prototyping.

## Testing
Run `npm test` to execute the Jest unit and integration tests (requires Node environment). See `test-report.md` for current coverage.
