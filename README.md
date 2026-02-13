# btrpa-scan

A Bluetooth Low Energy (BLE) scanner with advanced Resolvable Private Address (RPA) resolution. Discover nearby BLE devices, track a specific device by MAC address, or resolve privacy-randomized addresses using an Identity Resolving Key (IRK).

**Written by:** David Kennedy ([@HackingDave](https://twitter.com/HackingDave))
**Company:** [TrustedSec](https://www.trustedsec.com)

## Features

- **Discover All Devices** - Scan for all broadcasting BLE devices in range with signal strength, estimated distance, manufacturer data, and service UUIDs
- **Targeted Search** - Search for a specific device by MAC address and monitor every detection
- **IRK Resolution** - Resolve Resolvable Private Addresses against a known Identity Resolving Key to identify a device using randomized addresses for privacy
- **RSSI Filtering** - Filter out weak signals with a minimum RSSI threshold
- **CSV/JSON Export** - Export scan results to CSV or JSON files for further analysis
- **Verbose/Quiet Modes** - Verbose mode shows additional details (e.g. non-matching RPAs in IRK mode); quiet mode suppresses per-device output and shows only the summary

## Requirements

- Python 3.7+
- Bluetooth hardware
- OS support: macOS, Linux, Windows

### Platform Notes

| Platform | Notes |
|----------|-------|
| **macOS** | Uses CoreBluetooth. IRK mode leverages an undocumented API to retrieve real Bluetooth addresses instead of UUIDs. |
| **Linux** | May require `root` or `CAP_NET_ADMIN` capability for scanning. |
| **Windows** | Native WinRT Bluetooth API — real MAC addresses available natively. |

## Installation

```bash
git clone https://github.com/hackingdave/btrpa-scan.git
cd btrpa-scan
pip install -r requirements.txt
```

## Usage

```
usage: btrpa-scan.py [-h] [-a] [--irk HEX] [-t TIMEOUT] [--output {csv,json}]
                     [-o FILE] [-v | -q] [--min-rssi DBM] [mac]

BLE Scanner — discover all devices or hunt for a specific one

positional arguments:
  mac                   Target MAC address to search for (omit to scan all)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Scan for all broadcasting devices
  --irk HEX             Resolve RPAs using this Identity Resolving Key (32 hex chars)
  -t, --timeout TIMEOUT Scan timeout in seconds (default: 30, or infinite for --irk)
  --output {csv,json}   Output format (csv or json)
  -o, --output-file FILE
                        Output file path (default: btrpa-scan-results.<format>)
  -v, --verbose         Verbose mode — show additional details
  -q, --quiet           Quiet mode — suppress per-device output, show summary only
  --min-rssi DBM        Minimum RSSI threshold (e.g. -60) — ignore weaker signals
```

### Mode 1: Discover All Devices

Scan for all broadcasting BLE devices (default 30-second timeout):

```bash
python3 btrpa-scan.py --all
```

With a custom timeout:

```bash
python3 btrpa-scan.py --all -t 60
```

### Mode 2: Targeted Search

Search for a specific device by MAC address:

```bash
python3 btrpa-scan.py AA:BB:CC:DD:EE:FF
```

### Mode 3: IRK Resolution

Resolve Resolvable Private Addresses using an Identity Resolving Key. This mode runs indefinitely by default until stopped with `Ctrl+C`:

```bash
python3 btrpa-scan.py --irk 0123456789ABCDEF0123456789ABCDEF
```

The IRK can be provided in several formats:

| Format | Example |
|--------|---------|
| Plain hex | `0123456789ABCDEF0123456789ABCDEF` |
| Colon-separated | `01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF` |
| Dash-separated | `01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF` |
| 0x-prefixed | `0x0123456789ABCDEF0123456789ABCDEF` |

### RSSI Filtering

Only show devices with signal strength above a threshold:

```bash
python3 btrpa-scan.py --all --min-rssi -50
```

### Exporting Results

Export results to JSON:

```bash
python3 btrpa-scan.py --all --output json -o results.json -t 30
```

Export results to CSV (uses default filename `btrpa-scan-results.csv`):

```bash
python3 btrpa-scan.py --all --output csv -t 30
```

### Quiet and Verbose Modes

Run in quiet mode (summary only, no per-device output — useful with `--output`):

```bash
python3 btrpa-scan.py --all -q --output json -t 30
```

Run in verbose mode (show non-matching RPAs in IRK mode):

```bash
python3 btrpa-scan.py --irk 0123456789ABCDEF0123456789ABCDEF -v
```

## How RPA Resolution Works

Bluetooth Low Energy devices use Resolvable Private Addresses (RPAs) to prevent tracking. An RPA is a temporary MAC address that changes periodically, but can be resolved by anyone who possesses the device's Identity Resolving Key (IRK).

An RPA consists of:
- **prand** (3 bytes) - A random value with the top two bits set to `01`
- **hash** (3 bytes) - Computed as `AES-128-ECB(IRK, padding || prand)` truncated to 3 bytes

btrpa-scan implements the `ah()` function from the Bluetooth Core Specification (Vol 3, Part H, Section 2.2.2) to resolve these addresses in real time.

## Example Output

```
Mode: DISCOVER ALL - showing every broadcasting device
Timeout: 30s  |  Press Ctrl+C to stop
------------------------------------------------------------

============================================================
  DEVICE #1  -  seen 1x
============================================================
  Address      : AA:BB:CC:DD:EE:FF
  Name         : MyDevice
  RSSI         : -45 dBm
  TX Power     : -59 dBm
  Est. Distance: ~0.4 m
  Manufacturer : 0x004C -> 0215abcdef
  Timestamp    : 14:32:07
============================================================

------------------------------------------------------------
Scan complete - 30.0s elapsed
  Total detections : 142
  Unique devices   : 12
  Results written to btrpa-scan-results.json
```

## Stopping a Scan

Press `Ctrl+C` at any time to gracefully stop the scan and display summary statistics.

## License

See [LICENSE](LICENSE) for details.
