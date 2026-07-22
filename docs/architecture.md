# SurgeLab Architecture

## Overview
SurgeLab is a Windows desktop proxy configuration lab. It targets `sing-box` 1.13.14 and keeps imported proxy credentials, routing rules, generated configuration, and process logs on the local machine.

## High-Level Architecture
The application uses the **Electron** framework to provide a native desktop experience on Windows. It follows a multi-process architecture:

1.  **Frontend (Renderer Process):**
    *   **Technology:** HTML5, Vanilla JavaScript, and CSS (with a modern, premium dark-mode aesthetic).
    *   **Responsibilities:** Renders the GUI, handles user interactions, displays runtime status, and renders real-time logs.
2.  **Backend (Main Process / Local Controller Service):**
    *   **Technology:** Node.js (Electron Main Process).
    *   **Responsibilities:** Manages the `sing-box` binary lifecycle, validates generated JSON, stores profiles and rules, manages Windows system proxy state, and exposes a narrow IPC bridge to the frontend.
3.  **Core Adapter (Sing-box Process Manager):**
    *   **Responsibilities:** Checks a candidate config with `sing-box check` before atomically replacing the active config, then spawns, monitors, and terminates the child process while capturing stdout/stderr. TUN startup requires Windows administrator privileges and must survive a short runtime readiness window before being reported as running.
4.  **Profile Compiler & Rule Engine:**
    *   **Responsibilities:** Translates nodes, typed DNS settings, and first-match routing rules into the 1.13 schema. The local matcher previews domain, IPv4 CIDR, private-address, process, network, and port rules. Remote binary rule sets are explicitly deferred to sing-box.
5.  **Diagnostics Module:**
    *   **Responsibilities:** Measures TCP connection latency, performs DNS resolution through the selected local resolver, and inspects WebRTC ICE candidates for public-address exposure.
6.  **Storage:**
    *   **Responsibilities:** Local JSON storage (`profiles.json`, `rules.json`) with OS-backed encryption for primary node credentials when available.

## Data Flow
*   **User Input:** The user edits a proxy node or routing rule in the GUI.
*   **State Update:** The frontend sends IPC messages (e.g., `save-profile`) to the main process.
*   **Compilation:** The renderer invokes the shared Profile Compiler and sends the generated JSON over IPC.
*   **Validation:** The main process applies structural and loopback-binding checks, writes the config, and invokes the exact bundled core with `sing-box check`.
*   **Execution:** Only a validated config is started. Remote `geosite-cn` and `geoip-cn` binary rule sets are downloaded and cached by sing-box.
*   **Telemetry:** The Core Adapter pipes running status and logs back to the frontend via IPC.

## Security & Constraints
*   Controller only binds to `localhost` (`127.0.0.1`). No LAN exposure.
*   Windows system proxy state is persisted before mutation and restored on stop, child exit, app exit, or the next launch after an interrupted session.
*   Proxy passwords and UUIDs are masked in the UI by default.
*   TUN mode requests administrator privileges, enables dual-stack `strict_route`, DNS hijacking, and automatic interface detection.
*   No external API or web server.
*   Renderer sandbox, context isolation, navigation blocking, and a constrained preload bridge are enabled.
