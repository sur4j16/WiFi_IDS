import React, { useEffect, useState } from "react";
import "./StatsGrid.css";

function StatsGrid({ monitoringActive }) {
  const [stats, setStats] = useState({
    access_points: 0,
    active_clients: 0,
    alerts_today: 0,
    severity_level: "N/A",
  });

  useEffect(() => {
    if (!monitoringActive) {
      setStats([]);
      return;
    }
    const fetchStats = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/stats");
        const data = await response.json();
        setStats(data);
      } catch (error) {
        console.error("Failed to fetch stats:", error);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [monitoringActive]);

  const statDisplay = [
    { label: "Access Points", value: stats.access_points },
    { label: "Active Clients", value: stats.active_clients },
    { label: "Alerts Today", value: stats.alerts_today },
    { label: "Severity Level", value: stats.severity_level },
  ];

  return (
    <div className="stats-grid">
      {statDisplay.map((stat, index) => (
        <div className="stat-card" key={index}>
          <div className="stat-content">
            <div className="stat-number">{stat.value}</div>
            <div className="stat-label">{stat.label}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default StatsGrid;
