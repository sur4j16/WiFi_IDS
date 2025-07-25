import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import "./Header";
import Header from "./Header";
import "./Settings.css";

function Settings() {
  const [settings, setSettings] = useState({
    interface: "",
    ap_timeout: 300,
    client_timeout: 180,
    enable_channel_hopping: true,
    channel_hop_interval: 2,
  });

  useEffect(() => {
    fetch("http://localhost:5000/api/settings")
      .then((res) => res.json())
      .then(setSettings)
      .catch((error) => console.error("Failed to fetch settings:", error));
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setSettings((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    fetch("http://localhost:5000/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    })
      .then((res) => res.json())
      .then(() => {
        alert("Settings saved successfully!");
      })
      .catch((error) => {
        alert("Failed to save settings: " + error.message);
      });
  };

  return (
    <div>
      <Header />
      <div className="settings-page">
        <div className="settings-header">
          <Link to="/" className="back-btn">
            ← Back to Dashboard
          </Link>
          <h1>Settings</h1>
        </div>

        <div className="settings-content">
          <form onSubmit={handleSubmit} className="settings-form">
            <div className="form-group">
              <label>
                Interface:
                <input
                  name="interface"
                  value={settings.interface}
                  onChange={handleChange}
                  placeholder="e.g., wlan0"
                  required
                />
              </label>
            </div>

            <div className="form-group">
              <label>
                AP Timeout (seconds):
                <input
                  name="ap_timeout"
                  type="number"
                  value={settings.ap_timeout}
                  onChange={handleChange}
                  min="1"
                  required
                />
              </label>
            </div>

            <div className="form-group">
              <label>
                Client Timeout (seconds):
                <input
                  name="client_timeout"
                  type="number"
                  value={settings.client_timeout}
                  onChange={handleChange}
                  min="1"
                  required
                />
              </label>
            </div>

            <div className="form-group checkbox-group">
              <label>
                <input
                  name="enable_channel_hopping"
                  type="checkbox"
                  checked={settings.enable_channel_hopping}
                  onChange={handleChange}
                />
                Enable Channel Hopping
              </label>
            </div>

            <div className="form-group">
              <label>
                Channel Hop Interval (seconds):
                <input
                  name="channel_hop_interval"
                  type="number"
                  value={settings.channel_hop_interval}
                  onChange={handleChange}
                  min="1"
                  required
                />
              </label>
            </div>

            <div className="form-actions">
              <button type="submit" className="btn btn-primary">
                Save Settings
              </button>
              <Link to="/" className="btn btn-secondary">
                Cancel
              </Link>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default Settings;
