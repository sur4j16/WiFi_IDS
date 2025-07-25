import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import Settings from "./components/Settings";

function App() {
  const [monitoringActive, setMonitoringActive] = useState(false);

  const handleToggleMonitoring = () => {
    setMonitoringActive((prev) => !prev);
  };

  return (
    <Router>
      <div style={{ padding: "20px" }}>
        <Routes>
          <Route
            path="/"
            element={
              <Dashboard
                monitoringActive={monitoringActive}
                onToggleMonitoring={handleToggleMonitoring}
              />
            }
          />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
