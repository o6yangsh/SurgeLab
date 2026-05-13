# SurgeLab Architecture

## Overview
SurgeLab is a Windows desktop application prototype that acts as a local proxy configuration lab. It uses `sing-box` as the core engine, providing a user-friendly GUI to manage proxy profiles, configure routing rules, and diagnose network issues. 

## High-Level Architecture
The application uses the **Electron** framework to provide a native desktop experience on Windows. It follows a multi-process architecture:

1.  **Frontend (Renderer Process):**
    *   **Technology:** HTML5, Vanilla JavaScript, and CSS (with a modern, premium dark-mode aesthetic).
    *   **Responsibilities:** Renders the GUI, handles user interactions, displays runtime status, and renders real-time logs.
2.  **Backend (Main Process / Local Controller Service):**
    *   **Technology:** Node.js (Electron Main Process).
    *   **Responsibilities:** Binds the local controller service to `127.0.0.1`. Manages the `sing-box` binary lifecycle, compiles profiles into JSON configs, executes tests/diagnostics, stores configurations, and exposes an IPC bridge to the frontend.
3.  **Core Adapter (Sing-box Process Manager):**
    *   **Responsibilities:** Spawns, monitors, and terminates the `sing-box` child process. Captures stdout/stderr for logging, and handles restart/reload signals.
4.  **Profile Compiler & Rule Engine:**
    *   **Responsibilities:** Translates the internal UI state (node lists, DNS settings, routing rules) into valid `sing-box` JSON schemas. It also includes rule matching preview logic to simulate routing decisions.
5.  **Diagnostics Module:**
    *   **Responsibilities:** Tests node latency, performs DNS resolution tests, and runs WebRTC leak checks.
6.  **Storage:**
    *   **Responsibilities:** Local JSON storage (`profiles.json`) for configuration data, with encryption/masking for sensitive fields (passwords, UUIDs).

## Data Flow
*   **User Input:** The user edits a proxy node or routing rule in the GUI.
*   **State Update:** The frontend sends IPC messages (e.g., `save-profile`) to the main process.
*   **Compilation:** The main process updates local storage, invokes the Profile Compiler to generate the `sing-box.json` config, and writes it to disk.
*   **Execution:** The main process signals the Core Adapter to restart `sing-box` with the new config.
*   **Telemetry:** The Core Adapter pipes running status and logs back to the frontend via IPC.

## Security & Constraints
*   Controller only binds to `localhost` (`127.0.0.1`). No LAN exposure.
*   Proxy passwords and UUIDs are masked in the UI by default.
*   No external API or web server.
*   Operates purely for local personal network configuration.
