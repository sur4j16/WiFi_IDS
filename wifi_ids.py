from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth, Dot11Disas, Dot11Elt, Dot11EltRSN
from datetime import datetime
from collections import defaultdict,deque
from flask import Flask, jsonify, Response, request,cli
from flask_cors import CORS
import threading
import time
import queue
import logging
import sys
import json
import signal


cli.show_server_banner = lambda *args, **kwargs: None
# Set up logging for the application
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.getLogger('flask.app').setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Flask app and enable CORS
app = Flask(__name__)
CORS(app)
ids = None  # Global IDS instance

class WiFiIDS:
    """WiFi Intrusion Detection System for monitoring and detecting attacks on WiFi networks."""

    def __init__(self, interface="wlan0mon", enable_channel_hopping=True):
        """
        Initialize the WiFiIDS instance.

        Args:
            interface (str): Wireless interface to use for monitoring.
            enable_channel_hopping (bool): Enable automatic channel hopping.
        """
        self.interface = interface
        self.enable_channel_hopping = enable_channel_hopping
        self.current_channel = 1
        self.channel_hop_interval = 2
        self.channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        self.channel_index = 0        
        self._lock = threading.RLock()  # Lock for thread safety
        self.processing_threads = []
        self.ap_timeout = 300  # Timeout for APs
        self.client_timeout = 180  # Timeout for clients
        self._alert_lock = threading.RLock()  # Lock for alerts
        self.packet_queue = queue.Queue(maxsize=500)  # Queue for packets
        
        # Data structures for tracking APs, clients, and alerts
        self.detected_aps = {}
        self.ssid_to_bssids = defaultdict(set)
        self.client_probes = {}
        self.recent_clients = {}
        self.connected_clients = {}
        self.disconnected_clients = {}
        
        self.active_alerts = []
        self.deauth_counter = defaultdict(list)
        self.alerted_deauth = set()
        self.alerted_twins = set()
        
        self.logs = deque(maxlen=500)  # Store recent logs
        
        self.running = False
        self.shutdown_event = threading.Event()
        
        self.mac_vendors = self.load_oui("oui.txt")  # Load OUI database

    def clear_all(self):
        """Clear all tracked data and alerts."""
        with self._lock, self._alert_lock:
            self.detected_aps.clear()
            self.ssid_to_bssids.clear()
            self.client_probes.clear()
            self.recent_clients.clear()
            self.connected_clients.clear()
            self.disconnected_clients.clear()
            self.active_alerts.clear()
            self.deauth_counter.clear()
            self.alerted_deauth.clear()
            self.alerted_twins.clear()
            self.logs.clear()

    def load_oui(self, path):
        """Load OUI database for vendor lookup.

        Args:
            path (str): Path to the OUI file.

        Returns:
            dict: Mapping of OUI prefixes to vendor names.
        """
        if not os.path.exists(path):
            return {}
        
        vendors = {}
        try:
            with open(path, "r", encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) >= 2:
                            prefix = parts[0].strip().replace("-", ":").upper() 
                            vendor = parts[1].strip()
                            vendors[prefix] = vendor
                    elif "(base 16)" in line:
                        parts = line.split("(base 16)")
                        if len(parts) >= 2:
                            prefix = parts[0].strip().upper()
                            vendor = parts[1].strip()
                            vendors[prefix] = vendor
        except Exception as e:
            pass    
        return vendors

    def set_channel(self, channel):
        """Set the wireless interface to a specific channel (thread-safe).

        Args:
            channel (int): Channel number to set.

        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # Try setting channel using iwconfig
            result = subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.current_channel = channel
                return True
            
            # Try setting channel using iw (alternative)
            result = subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)], 
                                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.current_channel = channel
                return True
                
            self.log("WARN", f"Failed to set channel {channel}: {result.stderr}")
            return False
            
        except subprocess.TimeoutExpired:
            self.log("WARN", f"Timeout setting channel {channel}")
            return False
        except Exception as e:
            self.log("WARN", f"Error setting channel {channel}: {e}")
            return False

    def channel_hopper(self):
        """Background thread for channel hopping."""
        while self.running and not self.shutdown_event.is_set():
            try:
                channel = self.channels[self.channel_index]
                if self.set_channel(channel):
                    self.log("DEBUG", f"Switched to channel {channel}")
                
                self.channel_index = (self.channel_index + 1) % len(self.channels)
                
                # Sleep for the hop interval, interruptible by shutdown_event
                if self.shutdown_event.wait(timeout=self.channel_hop_interval):
                    break
                    
            except Exception as e:
                self.log("DEBUG", f"Error in channel hopper: {e}")
                if self.shutdown_event.wait(timeout=self.channel_hop_interval):
                    break
        
    def log(self, level, message):
        """Thread-safe logging with color and efficient size management.

        Args:
            level (str): Log level.
            message (str): Log message.
        """
        with self._lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = {
                "level": level,
                "time": timestamp,
                "message": message
            }
            self.logs.append(log_entry)
            
    def packet_capture_worker(self):
        """Capture packets from the wireless interface and enqueue them for processing."""
        def packet_handler(pkt):
            """Handle incoming packets and add to queue."""
            try:
                if not self.packet_queue.full():
                    self.packet_queue.put(pkt, block=False)
            except Exception as e:
                self.log("DEBUG",f"Error putting packet in queue: {e}")
            
        try:
            while self.running and not self.shutdown_event.is_set():
                sniff(
                    iface=self.interface, 
                    prn=packet_handler, 
                    store=0,
                    timeout=2
                )
        except Exception as e:
            self.log("ALERT", f"Packet capture failed: {e}")
            self.shutdown_event.set()

    def packet_processor_worker(self, worker_id):
        """Worker thread for processing packets from queue.

        Args:
            worker_id (int): Worker thread identifier.
        """
        self.log("INFO", f"Packet processor worker {worker_id} started")
        
        while self.running and not self.shutdown_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=1.0)
                try:
                    self.process_packet(pkt)
                except Exception as proc_e:
                    self.log("DEBUG", f"Worker {worker_id} packet processing error: {proc_e}")
                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.log("ALERT", f"Critical error in worker {worker_id}: {e}")
                continue
        self.log("INFO", f"Packet processor worker {worker_id} stopped")

    def process_packet(self, pkt):
        """Process individual packets (thread-safe).

        Args:
            pkt (scapy.packet.Packet): Packet to process.
        """
        if not pkt.haslayer(Dot11):
            return

        try:
            # Dispatch packet to appropriate handler based on type
            if pkt.haslayer(Dot11Beacon):
                self.process_beacon(pkt)
            elif pkt.haslayer(Dot11ProbeReq):
                self.process_probe(pkt)
            elif pkt.haslayer(Dot11Deauth):
                self.process_deauth(pkt)
            elif pkt.haslayer(Dot11Disas):
                self.process_disconnection(pkt, "disassociation")
            elif pkt.type == 2:
                self.process_connected_client(pkt)
            elif pkt.type == 0:
                if pkt.subtype == 1:  # Association Response
                    self.process_association_response(pkt)
                elif pkt.subtype == 3:  # Reassociation Response
                    self.process_association_response(pkt)
        except Exception as e:
            self.log("DEBUG", f"Error processing packet: {e}")

    def process_beacon(self, pkt):
        """Process beacon frames (thread-safe).

        Args:
            pkt (scapy.packet.Packet): Beacon packet.
        """
        try:
            bssid = pkt[Dot11].addr2
            if not bssid:
                return
            bssid = bssid.upper()
            
            ssid = "<hidden>"
            channel = None
            
            # Extract SSID from beacon
            if pkt.haslayer(Dot11Elt):
                try:
                    ssid_info = pkt[Dot11Elt].info
                    if ssid_info:
                        ssid = ssid_info.decode(errors="ignore").strip()
                        if not ssid:
                            ssid = "<hidden>"
                except Exception as e:
                    ssid = "<decode error>"
                    self.log("DEBUG",f"Error decoding SSID: {e}")
            
            # Extract channel from beacon
            try:
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 3 and elt.len == 1:
                        channel = elt.info[0]
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
            except Exception as e:
                channel = self.current_channel
                self.log("DEBUG",f"Error extracting channel: {e}")

            current_time = datetime.now()

            # Determine security type
            security = "Open"
            try:
                capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                if "privacy" in capability.lower():
                    if pkt.haslayer(Dot11EltRSN):
                        security = "WPA2"
                    else:
                        security = "WEP/WPA"
            except:
                pass

            # Extract signal strength if available
            signal_strength = None
            try:
                if hasattr(pkt, "dBm_AntSignal"):
                    signal_strength = pkt.dBm_AntSignal
            except:
                pass

            with self._lock:
                # New AP detected
                if bssid not in self.detected_aps:
                    vendor = self.lookup_vendor(bssid)
                    self.detected_aps[bssid] = {
                        "ssid": ssid,
                        "channel": channel,
                        "vendor": vendor,
                        "security": security,
                        "signal": signal_strength,
                        "last_seen": current_time,
                        "first_seen": current_time
                    }
                    
                    if ssid not in ["<hidden>", "<decode error>", ""]:
                        self.ssid_to_bssids[ssid].add(bssid)
                        
                    self.log("INFO", f"New AP detected: SSID='{ssid}' [{security}] CH={channel} {bssid} ({vendor})")
                else:
                    # Update existing AP info
                    old_ssid = self.detected_aps[bssid]["ssid"]
                    self.detected_aps[bssid].update({
                        "ssid": ssid,
                        "channel": channel,
                        "security": security,
                        "signal": signal_strength,
                        "last_seen": current_time
                    })
                    
                    if old_ssid != ssid and ssid not in ["<hidden>", "<decode error>", ""]:
                        if old_ssid in self.ssid_to_bssids:
                            self.ssid_to_bssids[old_ssid].discard(bssid)
                            if not self.ssid_to_bssids[old_ssid]:
                                del self.ssid_to_bssids[old_ssid]
                                self.alerted_twins.discard(old_ssid)
                        self.ssid_to_bssids[ssid].add(bssid)

                # Check for evil twin attack
                if ssid not in ["<hidden>", "<decode error>", ""] and len(ssid.strip()) > 0:
                    self._detect_evil_twin(ssid, bssid, current_time)
                    
        except Exception as e:
            self.log("DEBUG", f"Error processing beacon: {e}")

    def _detect_evil_twin(self, ssid, bssid, current_time):
        """Detect evil twin attacks.

        Args:
            ssid (str): SSID being checked.
            bssid (str): BSSID of the AP.
            current_time (datetime): Current timestamp.
        """
        bssids_for_ssid = self.ssid_to_bssids[ssid]
        
        if len(bssids_for_ssid) > 1:
            alert_key = f"{ssid}_{len(bssids_for_ssid)}"
            
            if alert_key not in self.alerted_twins:
                self.alerted_twins.add(alert_key)
                
                bssid_info = []
                for b in bssids_for_ssid:
                    ap_info = self.detected_aps[b]
                    bssid_info.append({
                        "bssid": b,
                        "channel": ap_info["channel"],
                        "vendor": ap_info["vendor"],
                        "security": ap_info["security"],
                        "first_seen": ap_info.get("first_seen", current_time)
                    })
                
                bssid_info.sort(key=lambda x: x["first_seen"])
                
                original = bssid_info[0]
                suspicious = bssid_info[1:]
                
                self.log("ALERT", f"Evil Twin detected: SSID '{ssid}' with {len(bssids_for_ssid)} BSSIDs")
                
                with self._alert_lock:
                    for susp in suspicious:
                        self.active_alerts.append({
                            "type": "evil_twin",
                            "ssid": ssid,
                            "original_bssid": original["bssid"],
                            "suspicious_bssid": susp["bssid"],
                            "original_channel": original["channel"],
                            "suspicious_channel": susp["channel"],
                            "original_vendor": original["vendor"],
                            "suspicious_vendor": susp["vendor"],
                            "severity": "critical",
                            "time": current_time.strftime("%H:%M:%S"),
                            "message": f"Evil Twin: {susp['bssid']} mimicking {original['bssid']} for SSID '{ssid}'"
                    })

    def lookup_vendor(self, mac):
        """Lookup vendor by MAC address using OUI database.

        Args:
            mac (str): MAC address.

        Returns:
            str: Vendor name or 'Unknown'.
        """
        if not mac or len(mac) < 8:
            return "Unknown"
        try:
            mac = mac.upper().replace("-", ":")
            oui_dash = "-".join(mac.split(":")[0:3])
            oui_hex = "".join(mac.split(":")[0:3])
            return self.mac_vendors.get(oui_dash, self.mac_vendors.get(oui_hex, "Unknown"))
        except Exception:
            return "Unknown"

    def process_probe(self, pkt):
        """Process probe request frames (thread-safe).

        Args:
            pkt (scapy.packet.Packet): Probe request packet.
        """
        try:
            mac = pkt[Dot11].addr2
            if not mac:
                return
                
            ssid = "<unknown>"
            if pkt.haslayer(Dot11Elt):
                try:
                    ssid_raw = pkt[Dot11Elt].info
                    if ssid_raw:
                        ssid = ssid_raw.decode(errors="ignore").strip()
                        if not ssid:
                            ssid = "any network"
                    else:
                        ssid = "any network"
                except Exception:
                    ssid = "<decode error>"

            with self._lock:
                if mac not in self.client_probes:
                    vendor = self.lookup_vendor(mac)
                    self.client_probes[mac] = ssid
                    self.recent_clients[mac] = time.time()
                    self.log("DEBUG", f"Probe: {mac} ({vendor}) is searching for '{ssid}'")
                    
        except Exception as e:
            self.log("DEBUG", f"Error processing probe: {e}")

    def process_connected_client(self, pkt):
        """Process data frames to detect connected clients (thread-safe).

        Args:
            pkt (scapy.packet.Packet): Data packet.
        """
        try:
            client_mac = None
            ap_mac = None
            
            addr1 = pkt.addr1
            addr2 = pkt.addr2
            
            if not addr1 or not addr2:
                return

            # Ignore broadcast frames
            if addr1.startswith("ff:ff:ff") or addr2.startswith("ff:ff:ff"):
                return

            addr1_upper = addr1.upper()
            addr2_upper = addr2.upper()
            
            with self._lock:
                # Determine which address is AP and which is client
                if addr1_upper in self.detected_aps:
                    ap_mac = addr1_upper
                    client_mac = addr2_upper
                elif addr2_upper in self.detected_aps:
                    ap_mac = addr2_upper
                    client_mac = addr1_upper
                else:
                    if self.is_likely_ap(addr1):
                        ap_mac = addr1_upper
                        client_mac = addr2_upper
                    elif self.is_likely_ap(addr2):
                        ap_mac = addr2_upper
                        client_mac = addr1_upper
                    else:
                        return

                # Add or update connected client info
                if client_mac not in self.connected_clients:
                    self.connected_clients[client_mac] = {
                        "ap_mac": ap_mac,
                        "last_seen": datetime.now().isoformat(),
                        "status": "connected"
                    }
                    self.log("DEBUG", f"Connected client detected via data: {client_mac} → {ap_mac}")
                else:
                    self.connected_clients[client_mac]["last_seen"] = datetime.now().isoformat()
                    
        except Exception as e:
            self.log("DEBUG", f"Error processing connected client: {e}")

    def is_likely_ap(self, mac):
        """Check if a MAC is likely an AP (BSSID).

        Args:
            mac (str): MAC address.

        Returns:
            bool: True if likely AP, False otherwise.
        """
        try:
            first_byte = int(mac.split(":")[0], 16)
            return not (first_byte & 0x02)
        except:
            return False

    def process_association_response(self, pkt):
        """Process association/reassociation response frames (thread-safe).

        Args:
            pkt (scapy.packet.Packet): Association response packet.
        """
        try:
            ap_mac = pkt.addr2
            client_mac = pkt.addr1
            
            if not ap_mac or not client_mac:
                return
                
            ap_mac = ap_mac.upper()
            client_mac = client_mac.upper()
            
            try:
                if hasattr(pkt, 'status') and pkt.status == 0:
                    with self._lock:
                        self.connected_clients[client_mac] = {
                            "ap_mac": ap_mac,
                            "last_seen": datetime.now().isoformat(),
                            "status": "connected",
                            "connection_time": datetime.now().isoformat()
                        }
                        
                        if client_mac in self.disconnected_clients:
                            del self.disconnected_clients[client_mac]
                        
                        ap_name = self.detected_aps.get(ap_mac, {}).get("ssid", "Unknown")
                        self.log("INFO", f"Client connected: {client_mac} → {ap_name} ({ap_mac})")
                    
            except Exception as e:
                self.log("DEBUG", f"Error checking association status: {e}")
                
        except Exception as e:
            self.log("DEBUG", f"Error processing association response: {e}")

    def process_disconnection(self, pkt, disconnect_type="disconnection"):
        """Process deauth and disassociation frames (thread-safe).

        Args:
            pkt (scapy.packet.Packet): Disconnection packet.
            disconnect_type (str): Type of disconnection.
        """
        try:
            source_mac = pkt.addr2
            dest_mac = pkt.addr1
            bssid = pkt.addr3
            
            if not source_mac or not dest_mac or not bssid:
                return
                
            source_mac = source_mac.upper()
            dest_mac = dest_mac.upper()
            bssid = bssid.upper()
            
            client_mac = None
            ap_mac = None
            
            with self._lock:
                # Determine which MAC is AP and which is client
                if source_mac in self.detected_aps:
                    ap_mac = source_mac
                    client_mac = dest_mac
                elif dest_mac in self.detected_aps:
                    ap_mac = dest_mac
                    client_mac = source_mac
                elif bssid in self.detected_aps:
                    ap_mac = bssid
                    if source_mac != bssid:
                        client_mac = source_mac
                    elif dest_mac != bssid:
                        client_mac = dest_mac
                
                # Move client from connected to disconnected
                if client_mac and client_mac in self.connected_clients:
                    client_info = self.connected_clients[client_mac].copy()
                    client_info["status"] = "disconnected"
                    client_info["disconnect_time"] = datetime.now().isoformat()
                    client_info["disconnect_type"] = disconnect_type
                    
                    self.disconnected_clients[client_mac] = client_info
                    del self.connected_clients[client_mac]
                    
                    ap_name = self.detected_aps.get(ap_mac, {}).get("ssid", "Unknown") if ap_mac else "Unknown"
                    self.log("INFO", f"Client disconnected ({disconnect_type}): {client_mac} from {ap_name}")
                    
        except Exception as e:
            self.log("DEBUG", f"Error processing {disconnect_type}: {e}")

    def process_deauth(self, packet):
        """Process deauth frames for attack detection.

        Args:
            packet (scapy.packet.Packet): Deauth packet.
        """
        try:
            if not packet.haslayer(Dot11Deauth):
                return

            source_mac = packet.addr2
            dest_mac = packet.addr1
            bssid = packet.addr3
            
            if not source_mac or not dest_mac:
                return
                
            current_time = time.time()
            time_str = datetime.now().strftime("%H:%M:%S")
            
            with self._lock:
                # Track deauth frames per source MAC
                self.deauth_counter[source_mac].append(current_time)
                self.deauth_counter[source_mac] = [
                    t for t in self.deauth_counter[source_mac] 
                    if current_time - t < 10
                ]
                
                # If too many deauths in short time, raise alert
                if len(self.deauth_counter[source_mac]) > 5:
                    if source_mac not in self.alerted_deauth:
                        self.alerted_deauth.add(source_mac)
                        self.log("ALERT", f"Deauth attack detected from {source_mac}")
                        with self._alert_lock:
                            self.active_alerts.append({
                                "mac": source_mac,
                                "dest_mac": dest_mac,
                                "bssid": bssid,
                                "type": "deauth_attack",
                                "severity": "high",
                                "vendor": self.lookup_vendor(source_mac),
                                "time": time_str,
                                "message": f"Deauth attack from {source_mac} to {dest_mac}"
                            })
                    
        except Exception as e:
            self.log("DEBUG", f"Error processing deauth: {e}")

    def cleanup_worker(self):
        """Background thread for cleaning up old entries."""
        while self.running and not self.shutdown_event.is_set():
            try:
                self.cleanup_old_entries()
                if self.shutdown_event.wait(timeout=30):
                    break
            except Exception as e:
                self.log("DEBUG", f"Error in cleanup worker: {e}")
                if self.shutdown_event.wait(timeout=30):
                    break

    def cleanup_old_entries(self):
        """Remove APs, clients, and attack tracking entries that haven't been seen recently (thread-safe)."""
        current_time = datetime.now()
        
        with self._lock:
            # Remove expired APs
            expired_aps = []
            for bssid, ap_info in self.detected_aps.items():
                last_seen = ap_info.get("last_seen", current_time)
                if (current_time - last_seen).total_seconds() > self.ap_timeout:
                    expired_aps.append(bssid)
            for bssid in expired_aps:
                ap_info = self.detected_aps[bssid]
                ssid = ap_info["ssid"]
                del self.detected_aps[bssid]
                if ssid in self.ssid_to_bssids:
                    self.ssid_to_bssids[ssid].discard(bssid)
                    if not self.ssid_to_bssids[ssid]:
                        del self.ssid_to_bssids[ssid]
                        keys_to_remove = [key for key in self.alerted_twins if key.startswith(f"{ssid}_")]
                        for key in keys_to_remove:
                            self.alerted_twins.discard(key)
                self.log("INFO", f"AP removed (timeout): SSID='{ssid}' {bssid}")

            # Remove expired clients
            current_timestamp = time.time()
            expired_clients = []
            for mac, last_seen_ts in self.recent_clients.items():
                if current_timestamp - last_seen_ts > self.client_timeout:
                    expired_clients.append(mac)
            for mac in expired_clients:
                del self.recent_clients[mac]
                if mac in self.client_probes:
                    del self.client_probes[mac]

            # Remove expired connected clients
            connected_timeout = 300
            expired_connected = []
            for mac, info in self.connected_clients.items():
                try:
                    last_seen = datetime.fromisoformat(info["last_seen"])
                    if (current_time - last_seen).total_seconds() > connected_timeout:
                        expired_connected.append(mac)
                except Exception as e:
                    expired_connected.append(mac)
                    self.log("DEBUG", f"Error parsing last_seen for {mac}: {e}")
            for mac in expired_connected:
                client_info = self.connected_clients[mac]
                ap_mac = client_info.get("ap_mac", "Unknown")
                ap_name = self.detected_aps.get(ap_mac, {}).get("ssid", "Unknown")
                del self.connected_clients[mac]
                self.log("INFO", f"Connected client removed (timeout): {mac} from {ap_name}")

            # Remove expired disconnected clients
            disconnect_timeout = 3600
            expired_disconnected = []
            for mac, info in self.disconnected_clients.items():
                try:
                    disconnect_time = datetime.fromisoformat(info.get("disconnect_time", info["last_seen"]))
                    if (current_time - disconnect_time).total_seconds() > disconnect_timeout:
                        expired_disconnected.append(mac)
                except:
                    expired_disconnected.append(mac)
            for mac in expired_disconnected:
                del self.disconnected_clients[mac]
                self.log("DEBUG", f"Disconnected client record removed: {mac}")

            # Remove expired deauth counters
            deauth_timeout = 600
            expired_deauth = []
            for mac, times in self.deauth_counter.items():
                self.deauth_counter[mac] = [t for t in times if time.time() - t < deauth_timeout]
                if not self.deauth_counter[mac]:
                    expired_deauth.append(mac)
            for mac in expired_deauth:
                del self.deauth_counter[mac]

            # Clean up alert tracking sets
            self.alerted_deauth = {mac for mac in self.alerted_deauth if mac in self.deauth_counter}
            self.alerted_twins = {key for key in self.alerted_twins if key.split("_")[0] in self.ssid_to_bssids}

        # Remove old alerts
        with self._alert_lock:
            alert_timeout = 300
            try:
                self.active_alerts = [
                    alert for alert in self.active_alerts 
                    if self._is_alert_recent(alert["time"], current_time, alert_timeout)
                ]
            except Exception as e:
                self.log("DEBUG", f"Error cleaning alerts: {e}")

    def get_recent_logs(self, limit=50):
        """Get recent log entries.

        Args:
            limit (int): Number of logs to return.

        Returns:
            list: Recent log entries.
        """
        return self.logs[-limit:]
    
    def _is_alert_recent(self, alert_time_str, current_time, timeout_seconds):
        """Check if alert is within timeout period.

        Args:
            alert_time_str (str): Alert time as string.
            current_time (datetime): Current time.
            timeout_seconds (int): Timeout in seconds.

        Returns:
            bool: True if alert is recent, False otherwise.
        """
        try:
            alert_time = datetime.strptime(alert_time_str, "%H:%M:%S").replace(
                year=current_time.year,
                month=current_time.month,
                day=current_time.day
            )
            return (current_time - alert_time).total_seconds() < timeout_seconds
        except Exception:
            return False
    
    def format_ap(self, bssid, ap):
        """Format AP information for API response.

        Args:
            bssid (str): BSSID of the AP.
            ap (dict): AP information.

        Returns:
            dict: Formatted AP data.
        """
        return {
            "ssid": ap["ssid"],
            "bssid": bssid,
            "channel": ap["channel"],
            "vendor": ap["vendor"],
            "security": ap.get("security", "Unknown"),
            "signal": ap.get("signal", None)
        }

    def format_connected_client(self, client_mac, info):
        """Format connected client information for API response.

        Args:
            client_mac (str): Client MAC address.
            info (dict): Client info.

        Returns:
            dict: Formatted client data.
        """
        ap_mac = info.get("ap_mac", "UNKNOWN")
        ap_info = self.detected_aps.get(ap_mac, {})
        ap_ssid = ap_info.get("ssid", "Unknown")
        return {
            "client_mac": client_mac,
            "client_vendor": self.lookup_vendor(client_mac),
            "ap_mac": ap_mac,
            "ap_vendor": self.lookup_vendor(ap_mac),
            "ap_name": ap_ssid,
            "last_seen": info["last_seen"],
            "status": info.get("status", "connected"),
            "connection_time": info.get("connection_time", info["last_seen"])
        }

    def format_disconnected_client(self, client_mac, info):
        """Format disconnected client information for API response.

        Args:
            client_mac (str): Client MAC address.
            info (dict): Client info.

        Returns:
            dict: Formatted client data.
        """
        ap_mac = info.get("ap_mac", "UNKNOWN")
        ap_info = self.detected_aps.get(ap_mac, {})
        ap_ssid = ap_info.get("ssid", "Unknown")
        return {
            "client_mac": client_mac,
            "client_vendor": self.lookup_vendor(client_mac),
            "ap_mac": ap_mac,
            "ap_vendor": self.lookup_vendor(ap_mac),
            "ap_name": ap_ssid,
            "last_seen": info["last_seen"],
            "status": info.get("status", "disconnected"),
            "disconnect_time": info.get("disconnect_time", "Unknown"),
            "disconnect_type": info.get("disconnect_type", "unknown"),
            "connection_time": info.get("connection_time", "Unknown")
        }

    def format_alert(self, alert):
        """Format alert information for API response.

        Args:
            alert (dict): Alert data.

        Returns:
            dict: Formatted alert data.
        """
        if alert["type"] == "evil_twin":
            return {
                "type": "evil_twin",
                "ssid": alert["ssid"],
                "original_bssid": alert["original_bssid"],
                "suspicious_bssid": alert["suspicious_bssid"],
                "original_channel": alert["original_channel"],
                "suspicious_channel": alert["suspicious_channel"],
                "original_vendor": alert["original_vendor"],
                "suspicious_vendor": alert["suspicious_vendor"],
                "severity": alert["severity"],
                "time": alert["time"],
                "message": alert["message"]
            }
        elif alert["type"] == "deauth_attack":
            return {
                "type": "DEAUTH_ATTACK",
                "source_mac": alert["mac"],
                "dest_mac": alert.get("dest_mac", "Unknown"),
                "bssid": alert.get("bssid", "Unknown"),
                "vendor": alert["vendor"],
                "severity": alert["severity"],
                "time": alert["time"],
                "message": alert["message"]
            }
        return alert

    def start(self):
        """Start the WiFi IDS with proper threading."""
        self.running = True
        self.shutdown_event.clear()
        self.log("INFO", f"WiFi IDS started on interface {self.interface}")
        
        # Start packet capture thread
        capture_thread = threading.Thread(target=self.packet_capture_worker, name="PacketCapture")
        capture_thread.daemon = True
        capture_thread.start()
        self.processing_threads.append(capture_thread)
        
        # Start packet processor threads
        for i in range(2):
            proc_thread = threading.Thread(
                target=self.packet_processor_worker, 
                args=(i,), 
                name=f"PacketProcessor-{i}"
            )
            proc_thread.daemon = True
            proc_thread.start()
            self.processing_threads.append(proc_thread)
        
        # Start channel hopper thread if enabled
        if self.enable_channel_hopping:
            channel_thread = threading.Thread(target=self.channel_hopper, name="ChannelHopper")
            channel_thread.daemon = True
            channel_thread.start()
            self.processing_threads.append(channel_thread)
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_worker, name="Cleanup")
        cleanup_thread.daemon = True
        cleanup_thread.start()
        self.processing_threads.append(cleanup_thread)
        
        self.log("INFO", f"Started {len(self.processing_threads)} worker threads")

    def stop(self):
        """Gracefully stop the IDS."""
        self.log("INFO", "Stopping WiFi IDS...")
        self.running = False
        self.shutdown_event.set()
        
        # Clear packet queue
        try:
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break
        except Exception as e:
            self.log("DEBUG", f"Error clearing queue: {e}")
        
        # Wait for threads to stop
        for thread in self.processing_threads:
            if thread.is_alive():
                self.log("DEBUG", f"Waiting for thread {thread.name} to stop...")
                thread.join(timeout=5)
                if thread.is_alive():
                    self.log("WARN", f"Thread {thread.name} did not stop gracefully")
        
        self.processing_threads.clear()
        self.log("INFO", "WiFi IDS stopped")

# --- Flask API Endpoints ---

@app.route('/api/aps')
def api_aps():
    """API endpoint to get detected access points."""
    if not ids:
        return jsonify([])
    with ids._lock:
        aps = [ids.format_ap(bssid,ap) for bssid,ap in ids.detected_aps.items()]
    return jsonify(aps)

@app.route("/api/probes")
def get_probes():
    """API endpoint to get client probe requests."""
    if not ids:
        return jsonify([])
    with ids._lock:
        probes = []
        for mac, ssid in ids.client_probes.items():
            probes.append({
                "mac": mac,
                "ssid": ssid,
                "vendor": ids.lookup_vendor(mac)
            })
    return jsonify(probes)

@app.route("/api/connected_clients")
def get_connected_clients():
    """API endpoint to get connected clients."""
    if not ids:
        return jsonify([])
    with ids._lock:
        clients = [ids.format_connected_client(client_mac,info) for client_mac,info in ids.connected_clients.items()]
    return jsonify(clients)

@app.route("/api/disconnected_clients")
def get_disconnected_clients():
    """API endpoint to get disconnected clients."""
    if not ids:
        return jsonify([])
    with ids._lock:
        clients = [ids.format_disconnected_client(client_mac,info) for client_mac,info in ids.disconnected_clients.items()]
    return jsonify(clients)

@app.route("/api/alerts")
def get_alerts():
    """API endpoint to get current alerts."""
    if not ids:
        return jsonify({"evil_twin_attacks": [], "deauth_attacks": []})
    with ids._alert_lock:
        evil_twins = [ids.format_alert(alert) for alert in ids.active_alerts if alert["type"]=="evil_twin"]
        deauth_attacks = [ids.format_alert(alert) for alert in ids.active_alerts if alert["type"]=="deauth_attack"]
    return jsonify({"evil_twin_attacks": evil_twins, "deauth_attacks": deauth_attacks})

@app.route("/api/logs")
def get_logs():
    """API endpoint to get recent logs."""
    if not ids:
        return jsonify([])
    with ids._lock:
        return jsonify(list(ids.logs)[-50:])

def format_relative_time(timestamp):
    """Format a timestamp as a relative time string.

    Args:
        timestamp (float): Unix timestamp.

    Returns:
        str: Relative time string.
    """
    try:
        seconds = time.time() - timestamp
        if seconds < 60:
            return f"{int(seconds)}s ago"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m ago"
        else:
            return f"{int(seconds // 3600)}h ago"
    except Exception as e:
        return f"Unknown ({e})"

@app.route("/api/clients")
def get_clients():
    """API endpoint to get recently seen clients."""
    if not ids:
        return jsonify([])
    clients_list = []
    for mac, last_seen_ts in ids.recent_clients.items():
        target_ssid = ids.client_probes.get(mac, "")
        clients_list.append({
            "mac": mac,
            "last_seen": format_relative_time(last_seen_ts),
            "name": ids.lookup_vendor(mac),
            "target": target_ssid
        })
    return jsonify(clients_list)

@app.route("/api/status")
def get_status():
    """API endpoint to get IDS status."""
    if not ids:
        return jsonify({"status": "not_initialized"})
    with ids._lock:
        status_data = {
            "status": "running",
            "interface": ids.interface,
            "current_channel": ids.current_channel,
            "channel_hopping": ids.enable_channel_hopping,
            "aps_detected": len(ids.detected_aps),
            "clients_detected": len(ids.client_probes),
            "connected_clients": len(ids.connected_clients),
            "disconnected_clients": len(ids.disconnected_clients),
            "alerts": len(ids.active_alerts)
        }
    return jsonify(status_data)

@app.route("/api/stats")
def get_stats():
    """API endpoint to get IDS statistics."""
    if not ids:
        return jsonify({
            "access_points": 0,
            "active_clients": 0,
            "alerts_today": 0,
            "severity_level": "N/A"
        })
    with ids._lock:
        severity = "Low"
        if len(ids.active_alerts) > 5:
            severity = "High"
        elif len(ids.active_alerts) > 2:
            severity = "Medium"
        return jsonify({
            "access_points": len(ids.detected_aps),
            "active_clients": len(ids.connected_clients),
            "alerts_today": len(ids.active_alerts),
            "severity_level": severity
        })

@app.route("/api/export/all")
def export_all():
    """API endpoint to export all IDS data."""
    if not ids:
        return jsonify({"error": "IDS not initialized"}), 400
    with ids._lock, ids._alert_lock:
        filtered_logs = [log for log in ids.logs if log["level"] in ("ALERT", "WARN", "INFO") and not log["message"].startswith("Switched to channel")]
        export_data = {
            "aps": [ids.format_ap(bssid, ap) for bssid, ap in ids.detected_aps.items()],
            "connected_clients": [ids.format_connected_client(mac, info) for mac, info in ids.connected_clients.items()],
            "disconnected_clients": [ids.format_disconnected_client(mac, info) for mac, info in ids.disconnected_clients.items()],
            "probes": [
                {"mac": mac, "ssid": ssid, "vendor": ids.lookup_vendor(mac)}
                for mac, ssid in ids.client_probes.items()
            ],
            "alerts": [ids.format_alert(alert) for alert in ids.active_alerts],
            "logs": filtered_logs
        }
    return Response(
        json.dumps(export_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=wifi_ids_export.json"}
    )

@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    """API endpoint to clear all alerts."""
    if not ids:
        return jsonify({"status": "not_initialized"}), 400
    with ids._alert_lock:
        ids.active_alerts.clear()
    return jsonify({"status": "cleared"})

@app.route("/api/settings", methods=["GET"])
def get_settings():
    """API endpoint to get IDS settings."""
    if not ids:
        return jsonify({})
    with ids._lock:
        return jsonify({
            "interface": ids.interface,
            "ap_timeout": ids.ap_timeout,
            "client_timeout": ids.client_timeout,
            "enable_channel_hopping": ids.enable_channel_hopping,
            "channel_hop_interval": ids.channel_hop_interval,
        })

@app.route("/api/settings", methods=["POST"])
def save_settings():
    """API endpoint to update IDS settings."""
    if not ids:
        return jsonify({"status": "not_initialized"}), 400
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    try:
        with ids._lock:
            if "interface" in data:
                ids.interface = data["interface"]
            if "ap_timeout" in data:
                ids.ap_timeout = int(data["ap_timeout"])
            if "client_timeout" in data:
                ids.client_timeout = int(data["client_timeout"])
            if "enable_channel_hopping" in data:
                ids.enable_channel_hopping = bool(data["enable_channel_hopping"])
            if "channel_hop_interval" in data:
                ids.channel_hop_interval = int(data["channel_hop_interval"])
        return jsonify({"status": "settings_updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/clear/all', methods=['POST'])
def clear_all_data():
    """API endpoint to clear all IDS data."""
    try:
        ids.clear_all()
        return jsonify({
            'success': True,
            'message': 'All data cleared successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to clear data: {str(e)}'
        }), 500

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global ids
    print("\nReceived interrupt signal. Shutting down...")
    if ids:
        ids.stop()
    sys.exit(0)

def start_flask():
    """Start Flask in a separate thread."""
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

if __name__ == "__main__":
    signal.signal(signal.SIGINT,signal_handler)
    try:
        ids = WiFiIDS(interface="wlan0mon", enable_channel_hopping=True)
        flask_thread = threading.Thread(target=start_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        print("Flask API started on http://0.0.0.0:5000")
        print("Starting WiFi IDS...")
        print("Press Ctrl+C to stop")
        
        # Start the IDS
        ids.start()
        
        while True:
            time.sleep(1)
        
    except KeyboardInterrupt:
        print("\nShutting down...")
        if ids:
            ids.running = False
    except Exception as e:
        print(f"Error: {e}")