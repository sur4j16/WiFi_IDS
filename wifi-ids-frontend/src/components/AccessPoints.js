import React, { useEffect, useState } from "react";
import "./AccessPoints.css";
import "./Card.css";

function AccessPoints({ monitoringActive }) {
  const [accessPoints, setAccessPoints] = useState([]);

  useEffect(() => {
    if (!monitoringActive) {
      setAccessPoints([]);
      return;
    }

    const fetchAPs = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/aps");
        const data = await response.json();
        setAccessPoints(data);
      } catch (error) {
        console.log("Failed to fetch access points ", error);
      }
    };

    fetchAPs();
    const interval = setInterval(fetchAPs, 5000);
    return () => clearInterval(interval);
  }, [monitoringActive]);

  return (
    <div className="access-points">
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Access Points</h2>
        </div>
        <div className="card-content scrollbar-hide">
          <div className="ap-list">
            {accessPoints.map((ap, index) => (
              <div className="ap-item" key={index}>
                <div className="ap-header">
                  <span className="ap-ssid">{ap.ssid}</span>
                  <span
                    className={`crypto-badge ${
                      ap.security === "Open" ? "crypto-open" : "crypto-wpa"
                    }`}
                  >
                    {ap.security}
                  </span>
                </div>
                <div className="ap-details">
                  <span>{ap.bssid}</span>
                  <span className="channel-indicator">Ch {ap.channel}</span>
                  <span>{ap.signal} dBm</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default AccessPoints;
