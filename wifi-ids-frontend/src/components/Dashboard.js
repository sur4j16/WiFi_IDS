import React from "react";
import Header from "./Header";
import StatsGrid from "./StatsGrid";
import Button from "./Buttons";
import AccessPoints from "./AccessPoints";
import LiveAlerts from "./LiveAlerts";
import "./Dashboard.css";
import ReactClients from "./RecentClients";
import SystemLogs from "./SystemLogs";

function Dashboard({
  monitoringActive,
  onToggleMonitoring,
  onNavigateToSettings,
}) {
  return (
    <div className="dashboard">
      <Header monitoringActive={monitoringActive} />
      <div className="main-container">
        <StatsGrid monitoringActive={monitoringActive} />
        <Button
          monitoringActive={monitoringActive}
          onToggleMonitoring={onToggleMonitoring}
          onNavigateToSettings={onNavigateToSettings}
        />
        <AccessPoints monitoringActive={monitoringActive} />
        <LiveAlerts monitoringActive={monitoringActive} />
        <ReactClients monitoringActive={monitoringActive} />
        <SystemLogs monitoringActive={monitoringActive} />
      </div>
    </div>
  );
}

export default Dashboard;
