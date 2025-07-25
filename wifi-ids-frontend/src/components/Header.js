import React from "react";
import "./Header.css";

function Header({ monitoringActive }) {
  return (
    <header className="header">
      <div className="header-content">
        <div className="logo">
          <div className="logo-icon">
            <img src="/images/wifi-svgrepo-com.svg" alt="Wifi-Logo" />
          </div>
          <div>
            <h1>WiFi IDS</h1>
            <p style={{ fontSize: "0.875rem", color: "#94a3b8" }}>
              Intrusion Detection System
            </p>
          </div>
        </div>
        <div
          className={`status-indicator ${
            monitoringActive ? "active" : "inactive"
          }`}
        >
          <span
            className={`status-dot ${monitoringActive ? "active" : "inactive"}`}
          ></span>
          <span style={{ marginLeft: 8 }}>
            {monitoringActive ? "Monitoring Active" : "Monitoring Off"}
          </span>
        </div>
      </div>
    </header>
  );
}

export default Header;
