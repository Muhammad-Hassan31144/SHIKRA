import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import MemoryAnalysis from './pages/MemoryAnalysis';
import NetworkAnalysis from './pages/NetworkAnalysis';
import ProcessMonitor from './pages/ProcessMonitor';
import CombinedReport from './pages/CombinedReport';
import useCyberStore from './store/cyberStore';
import { sampleMemoryData, sampleNetworkData, sampleProcmonData } from './utils/sampleData';
import './App.css';

function App() {
  const { setThreatData, setMetrics } = useCyberStore();

  useEffect(() => {
    // Load sample data on app initialization
    setThreatData('memory', sampleMemoryData);
    setThreatData('network', sampleNetworkData);
    setThreatData('procmon', sampleProcmonData);

    // Calculate and set metrics
    setMetrics({
      totalThreats: 23,
      criticalAlerts: 5,
      riskScore: 8.7,
      activeConnections: 47,
    });
  }, [setThreatData, setMetrics]);

  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/memory" element={<MemoryAnalysis />} />
          <Route path="/network" element={<NetworkAnalysis />} />
          <Route path="/procmon" element={<ProcessMonitor />} />
          <Route path="/combined" element={<CombinedReport />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
