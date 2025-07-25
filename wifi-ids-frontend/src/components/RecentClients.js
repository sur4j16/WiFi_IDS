import React, { useEffect, useState } from "react";
import "./RecentClients.css";
import "./Card.css";

function ConnectedClients({ monitoringActive }) {
  const [clients, setClients] = useState([]);

  useEffect(() => {
    if (!monitoringActive) {
      setClients([]);
      return;
    }
    const fetchClients = async () => {
      try {
        const response = await fetch(
          "http://localhost:5000/api/connected_clients"
        );
        const data = await response.json();
        console.log("Fetched connected clients:", data);
        setClients(data);
      } catch (error) {
        console.error("Failed to fetch connected clients", error);
      }
    };

    fetchClients();
    const interval = setInterval(fetchClients, 5000);
    return () => clearInterval(interval);
  }, [monitoringActive]);

  return (
    <div className="connected-clients">
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Connected Clients</h2>
        </div>
        <div className="card-content scrollbar-hide">
          <div className="client-list">
            {clients.map((client, index) => (
              <div className="client-item" key={index}>
                <div className="client-top">
                  <span className="client-name">{client.client_vendor}</span>
                  <span className="client-time">{client.last_seen}</span>
                </div>
                <div className="client-details">
                  MAC: {client.client_mac} → Connected to: {client.ap_mac} (
                  {client.ap_name})
                </div>
              </div>
            ))}
            {clients.length === 0 && (
              <div className="client-item">No clients currently connected.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default ConnectedClients;
