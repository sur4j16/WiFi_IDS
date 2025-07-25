import React from "react";
import { Link } from "react-router-dom";
import "./Button.css";

function Button({ onToggleMonitoring, monitoringActive }) {
  const handleToggleMonitoring = async () => {
    if (monitoringActive) {
      try {
        const response = await fetch("http://localhost:5000/api/clear/all", {
          method: "POST",
        });
        if (!response.ok) throw new Error("Failed to clear data");
        console.log("Monitoring stopped and data cleared.");
      } catch (error) {
        alert("Failed to stop monitoring or clear data: " + error.message);
      }
    }

    onToggleMonitoring();
  };

  const handleExport = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/export/all");
      if (!response.ok) throw new Error("Failed to export data");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "wifi_ids_export.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      alert("Export failed: " + error.message);
    }
  };

  const handleClearAlerts = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/alerts/clear", {
        method: "POST",
      });
      if (!response.ok) throw new Error("Failed to clear alerts");
      alert("Alerts cleared successfully");
    } catch (error) {
      alert("Clear alerts failed: " + error.message);
    }
  };

  return (
    <div className="control-panel">
      <button className="btn btn-primary" onClick={handleToggleMonitoring}>
        {monitoringActive ? "Stop Monitoring" : "Start Monitoring"}
      </button>
      <button className="btn btn-secondary" onClick={handleExport}>
        Export Data
      </button>
      <button className="btn btn-secondary" onClick={handleClearAlerts}>
        Clear Alerts
      </button>
      <Link to="/settings" className="btn btn-secondary">
        Settings
      </Link>
    </div>
  );
}

export default Button;
