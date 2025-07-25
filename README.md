# WiFi Intrusion Detection System (WiFi IDS)

A Python-based WiFi Intrusion Detection System that monitors wireless traffic, detects suspicious activities (such as deauthentication attacks and evil twin APs), and provides a REST API for real-time monitoring and management. Includes a React frontend for visualization and control.

---

## Features

- **Real-time WiFi monitoring** using Scapy
- **Detection of:**
  - Deauthentication attacks
  - Evil twin access points
  - Client probes and associations
- **REST API** (Flask) for integration and frontend
- **Configurable settings** (interface, timeouts, channel hopping, etc.)
- **Export logs and data** as JSON
- **Frontend dashboard** (React) for live monitoring and control

---

## Requirements

- Python 3.8+ (tested and working with Python 3.11)
- Linux (with wireless interface in monitor mode)
- [Scapy](https://scapy.net/)
- Flask, flask-cors
- Node.js & npm (for frontend)
- **Root privileges** (required for packet capture)

> **Important:**  
> Your WiFi adapter **must support monitor mode** and be set to monitor mode for this IDS to work.  
> Use tools like `airmon-ng` to enable monitor mode (see below).

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Prepare Wireless Interface

Put your WiFi interface into monitor mode (e.g., using `airmon-ng`):

```bash
sudo airmon-ng start wlan0
```

This will create an interface like `wlan0mon`.

**Verify your monitor interface exists:**

```bash
iwconfig
# or
ip link show
```

### 2. Start the Backend

**Important:** Run with sudo and preserve environment variables if using a virtual environment:

```bash
sudo python wifi_ids.py
```

- The Flask API will run on [http://localhost:5000](http://localhost:5000)
- The IDS will start monitoring on the configured interface.

### 3. Start the Frontend

```bash
cd wifi-ids-frontend
npm install
npm start
```

- The React app will run on [http://localhost:3000](http://localhost:3000)

---

## Troubleshooting

### Common Issues

#### 1. "Interface 'wlan0mon' not found"

**Problem:** Monitor interface doesn't exist or has different name.

**Solutions:**

- Check available interfaces: `iwconfig` or `ip link show`
- Verify monitor mode is enabled: `sudo airmon-ng start wlan0`
- Update interface name in settings or command line
- Common monitor interface names: `wlan0mon`, `wlan1mon`, `mon0`

#### 2. "command failed: No such device (-19)"

**Problem:** Interface exists but is not properly configured for monitor mode.

**Solutions:**

- Kill conflicting processes: `sudo airmon-ng check kill`
- Restart monitor mode:
  ```bash
  sudo airmon-ng stop wlan0mon
  sudo airmon-ng start wlan0
  ```
- If issues persist, try stopping NetworkManager: `sudo systemctl stop NetworkManager`

### Pre-flight Checklist

Before running the IDS, ensure:

1. WiFi adapter supports monitor mode
2. Monitor mode is enabled (`sudo airmon-ng start wlan0`)
3. Monitor interface exists (`iwconfig` shows `wlan0mon` or similar)
4. Required Python packages installed (`pip install -r requirements.txt`)
5. Running with appropriate privileges (`sudo`)

_Note: Stopping NetworkManager is usually not required, but may help if you encounter interface conflicts._

---

## Configuration

You can change IDS settings (interface, timeouts, channel hopping, etc.) via the frontend **Settings** page or by POSTing to `/api/settings`.

Example:

```json
{
  "interface": "wlan0mon",
  "ap_timeout": 300,
  "client_timeout": 180,
  "enable_channel_hopping": true,
  "channel_hop_interval": 2
}
```

---

## Stopping

Press `Ctrl+C` in the backend terminal to gracefully stop the IDS and API.

To restore normal WiFi functionality:

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

---

## Notes

- **Monitor mode is required:** Your WiFi adapter must support monitor mode and be set to monitor mode before running the IDS.
- **Root privileges required:** You must run as root or with sufficient privileges to capture WiFi packets.
- **NetworkManager:** Usually works alongside NetworkManager, but stopping it may help resolve interface conflicts if encountered.
- This tool is for educational and authorized testing purposes only. Ensure you have proper authorization before monitoring wireless networks.

---
