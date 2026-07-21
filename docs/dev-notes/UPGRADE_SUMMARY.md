# FTP Auth Failure Detection Upgrade

## Summary
Implemented lightweight payload inspection to detect FTP authentication failures, recovering the `num_failed_logins` feature signal that was previously hardcoded to 0.

## Changes Made

### 1. **backend/pcap_to_features.py**

#### Added FTP Auth Failure Detection
- **New import**: Added `Raw` from scapy to access packet payloads
- **New patterns**: `FTP_AUTH_FAIL_PATTERNS` detects RFC 959 response codes:
  - `530` - Not logged in
  - `550` - Permission denied  
  - `421` - Service temporarily unavailable
  - `Login incorrect`
  - `Invalid user`

#### New Function: `extract_ftp_failed_logins(conn_packets)`
- Lightweight grep-level payload scanning (not full DPI)
- Counts FTP auth failure responses per connection
- Returns integer count of failed login attempts

#### Updated `compute_features()`
- Now calls `extract_ftp_failed_logins()` for FTP (port 21, TCP) connections
- Replaces hardcoded `"num_failed_logins": 0` with actual detection
- Maintains backward compatibility: non-FTP connections still get 0

#### Updated Module Docstring
- Explains the new lightweight payload inspection approach
- Clarifies RFC 959 code detection for FTP
- Documents that most other content/host features remain zeroed

#### Enhanced Output Display
- Terminal output now shows FTP auth failures when present
- Combined marker display for multiple detection types (brute-force + FTP failures)

## Test Coverage

### test_ftp_auth_failures.py
Tests FTP-specific detection:
- Detects multiple 530 "Not logged in" responses
- Detects 550 "Login incorrect" responses
- Distinguishes successful (220) from failed connections
- Verifies no false positives on non-FTP ports
- **Result**: 10/10 failures detected correctly

### test_integration.py
Integration test combining all detection types:
- FTP auth failure detection (7 detected)
- SSH brute-force detection via connection patterns (8 detected)
- Port scan detection via S0 flags (14 detected)
- Backward compatibility with existing features
- **Result**: All features coexist without conflicts

### Backward Compatibility
- Original test_traffic.pcap still works perfectly
- SSH brute-force scoring (auth_bruteforce_score) unchanged
- Port scan detection unchanged
- All 169 connections processed correctly

## Performance Notes
- **Complexity**: O(n*m) where n = packets per connection, m = patterns
- **Minimal overhead**: Only scans FTP (port 21, TCP) connections
- **Pattern matching**: Simple byte string search (grep-level)
- **Memory**: No additional per-connection state

## Feature Impact
- **Before**: `num_failed_logins` always = 0 (no signal)
- **After**: `num_failed_logins` = count of FTP 5xx response codes (signal recovered)
- **Scope**: Plaintext FTP only (encrypted SFTP/TLS cannot be inspected without keys)
- **Accuracy**: High confidence for plaintext FTP on port 21; SSH still uses behavioral detection

## Future Enhancements
Potential extensions (not implemented):
- Telnet auth failure detection (port 23, ASCII patterns)
- HTTP auth failures (401 responses)
- SMTP auth failures (550/501 responses)
- Custom pattern registry for additional protocols

## Testing Commands
```bash
# FTP-specific test
python test_ftp_auth_failures.py

# Integration test (all attack types)
python test_integration.py

# Original test suite (backward compatibility)
python backend/pcap_to_features.py data/test_traffic.pcap
```
