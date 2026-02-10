import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import TopologyPage from "./pages/TopologyPage";
import ServiceDetailPage from "./pages/ServiceDetailPage";
import ConnectionsPage from "./pages/ConnectionsPage";
import RequestsPage from "./pages/RequestsPage";
import DashboardPage from "./pages/DashboardPage";

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    minHeight: "100vh",
    backgroundColor: "#0d1117",
    color: "#e6edf3",
  },
  main: {
    flex: 1,
    padding: "24px",
    marginLeft: "240px",
    minHeight: "100vh",
  },
};

const App: React.FC = () => {
  return (
    <div style={styles.container}>
      <Sidebar />
      <main style={styles.main}>
        <Routes>
          <Route path="/" element={<Navigate to="/topology" replace />} />
          <Route path="/topology" element={<TopologyPage />} />
          <Route path="/services/:name" element={<ServiceDetailPage />} />
          <Route path="/connections" element={<ConnectionsPage />} />
          <Route path="/requests" element={<RequestsPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
        </Routes>
      </main>
    </div>
  );
};

export default App;
