import React, { useEffect, useState } from "react";
import "./LiveAlerts.css";
import "./Card.css";

function LiveAlerts({ monitoringActive }) {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    if (!monitoringActive) {
      setAlerts([]);
      return;
    }

    const fetchAlerts = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/alerts");
        const data = await response.json();
        console.log("Fetched alerts: ", data);

        const deauthAlerts = (data.deauth_attacks || []).map((entry) => ({
          id: `${entry.source_mac}-deauth-${entry.dest_mac}`,
          type: "deauth_attack",
          severity: entry.severity || "high",
          message: `Access Point ${entry.source_mac} is deauthenticating client ${entry.dest_mac}.`,
          time: entry.time || new Date().toLocaleTimeString(),
        }));

        const evilTwinAlerts = (data.evil_twin_attacks || []).map((entry) => ({
          id: `${entry.suspicious_bssid}-eviltwin-${entry.original_bssid}`,
          type: "evil_twin_attack",
          severity: entry.severity || "high",
          message: `Fake AP ${entry.suspicious_bssid} mimicking ${entry.original_bssid} detected as an Evil Twin.`,
          time: entry.time || new Date().toLocaleTimeString(),
        }));

        const allAlerts = [...deauthAlerts, ...evilTwinAlerts];

        allAlerts.sort((a, b) => new Date(b.time) - new Date(a.time));

        setAlerts(allAlerts);
      } catch (error) {
        console.error("Failed to fetch alerts:", error);
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, [monitoringActive]);

  const formatType = (type) => {
    if (typeof type !== "string") return "ALERT";
    return type.replace(/_/g, " ").toUpperCase();
  };

  const formatSeverity = (severity) => {
    if (typeof severity !== "string") return "INFO";
    return severity.toUpperCase();
  };

  return (
    <div className="live-alerts">
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Live Alerts</h2>
        </div>
        <div className="card-content scrollbar-hide">
          <div className="alert-list">
            {alerts.length === 0 ? (
              <p className="no-alerts">No active alerts at this time.</p>
            ) : (
              alerts.map((alert, index) => (
                <div
                  className={`alert-item ${alert.severity || "info"}`}
                  key={alert.id || index}
                >
                  <div className="alert-header">
                    <span className="alert-type">{formatType(alert.type)}</span>
                    <span
                      className={`severity-badge severity-${
                        alert.severity || "info"
                      }`}
                    >
                      {formatSeverity(alert.severity)}
                    </span>
                  </div>
                  <p>{alert.message || "Suspicious activity detected."}</p>
                  <div className="alert-time">
                    {alert.time || "Time not available"}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default LiveAlerts;
