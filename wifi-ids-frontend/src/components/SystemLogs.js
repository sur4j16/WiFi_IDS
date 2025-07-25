import React, { useEffect, useState } from "react";
import "./SystemLogs.css";

function SystemLogs({ monitoringActive }) {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    if (!monitoringActive) {
      setLogs([]);
      return;
    }

    const fetchLogs = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/logs");
        const data = await response.json();
        setLogs(data);
      } catch (error) {
        console.log("Failed to fetch logs ", error);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 3000);
    return () => clearInterval(interval);
  }, [monitoringActive]);

  const getColor = (level) => {
    switch (level) {
      case "INFO":
        return "#10b981";
      case "DEBUG":
        return "#3b82f6";
      case "WARN":
        return "#f59e0b";
      case "ALERT":
        return "#ef4444";
      default:
        return "#e2e8f0";
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">System Logs</h2>
      </div>
      <div className="card-content scrollbar-hide">
        <div className="logs-list">
          {logs
            .filter(
              (log) =>
                log.level !== "DEBUG" &&
                !(
                  log.level === "INFO" &&
                  (log.message.includes("Packet processor worker") ||
                    (log.message.includes("Started") &&
                      log.message.includes("worker threads")))
                )
            )
            .map((log, index) => (
              <div className="log-entry" key={index}>
                <span
                  className="log-level"
                  style={{ color: getColor(log.level) }}
                >
                  [{log.level}]
                </span>{" "}
                {log.time} - {log.message}
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

export default SystemLogs;
