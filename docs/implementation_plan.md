# SurgeLab Implementation Plan

## Phase 1: Project Setup and Boilerplate
- Create the Electron directory structure (`src`, `docs`, `tests`).
- Write `package.json` with dependencies for Electron.
- Create the `main.js` for the backend Local Controller Service and `preload.js` for secure IPC.
- Create `index.html`, `styles.css`, and `renderer.js` for the UI.

## Phase 2: User Interface Design
- Implement a premium dark-mode sidebar layout (Overview, Nodes, Rules, DNS, Diagnostics).
- Create views for listing proxy nodes and rules.
- Add forms to import nodes via URI and edit their parameters.

## Phase 3: Profile Parser & Rule Engine Mock
- Implement URI parsers for `ss://`, `trojan://`, `vmess://`, `vless://`, and `hy2://` within the frontend or backend mockup.
- Implement the UI logic to construct routing rule lists and assign them to Rule Groups.
- Build the "Rule Preview Tool" UI to allow users to input a domain/IP and see the simulated outcome.

## Phase 4: Sing-box Configuration Compiler
- Create a JavaScript module in the backend (`compiler.js`) to take the internal profiles and rules and convert them to `sing-box.json`.
- Implement modes: System Proxy vs. TUN.
- Enforce the 127.0.0.1 controller binding.

## Phase 5: Core Adapter & Diagnostics
- Create the Node.js `child_process` wrapper for `sing-box` (start/stop/restart logic).
- Implement the mock handlers for diagnostic tests (Latency, DNS, WebRTC leak warning UI).

## Phase 6: Testing & Review
- Provide `package.json` scripts for unit/integration tests using standard JS tools like Jest.
- Create a set of sample profiles and a generated JSON config for validation.
- Capture screenshots via browser subagent.
