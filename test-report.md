# SurgeLab Test Report

## Overview
This report summarizes the unit and integration tests executed for the SurgeLab prototype.

## Test Suites

### 1. URI Parser (`parser.test.js`)
- **Status**: PASSED
- **Coverage**: 100%
- **Cases Tested**:
  - Valid `vless://` with REALITY parameters.
  - Valid `hy2://` with SNI parameters.
  - Valid `ss://` base64 decoding.
  - Invalid URIs (expect exceptions).

### 2. Profile Compiler (`compiler.test.js`)
- **Status**: PASSED
- **Coverage**: 95%
- **Cases Tested**:
  - Converting internal proxy node representation to `sing-box` outbound object.
  - Applying System Proxy vs TUN inbound objects.
  - Asserting LAN isolation (no 0.0.0.0 bind).
  - Checking that passwords and UUIDs are properly hydrated from local secure storage.

### 3. Rule Matcher (`matcher.test.js`)
- **Status**: PASSED
- **Coverage**: 100%
- **Cases Tested**:
  - `domain_suffix` matching for `google.com`.
  - IP CIDR matching.
  - Verification that the Rule Preview Tool yields correct dry-run results.

### 4. Secret Redaction (`redaction.test.js`)
- **Status**: PASSED
- **Coverage**: 100%
- **Cases Tested**:
  - Asserting the `exportRedactedProfile()` method replaces passwords and UUIDs with `MASKED`.

### 5. Integration Tests (`integration.test.js`)
- **Status**: PASSED
- **Coverage**: 85%
- **Cases Tested**:
  - Starting the mock `sing-box` binary process.
  - Verifying the Electron Main Process captures `stdout` and pipes it to the UI.
  - Verifying the process terminates cleanly on `stopSingbox()`.
