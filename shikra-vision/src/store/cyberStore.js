import { create } from 'zustand';
import { sampleCombinedData } from '../utils/sampleData';

// Create store for cybersecurity dashboard data
const useCyberStore = create((set, get) => ({
  // Current view state
  currentView: 'dashboard',
  setCurrentView: (view) => set({ currentView: view }),
  
  // Threat data
  threatData: {
    memory: null,
    network: null,
    procmon: null,
    combined: null,
    combinedAnalysis: sampleCombinedData, // Load sample combined data
  },
  
  // Load threat data
  setThreatData: (type, data) => set((state) => ({
    threatData: {
      ...state.threatData,
      [type]: data
    }
  })),
  
  // Filters and search
  filters: {
    riskLevel: 'all',
    timeRange: '24h',
    threatType: 'all',
  },
  setFilters: (newFilters) => set((state) => ({
    filters: { ...state.filters, ...newFilters }
  })),
  
  searchQuery: '',
  setSearchQuery: (query) => set({ searchQuery: query }),
  
  // Dashboard metrics
  metrics: {
    totalThreats: 0,
    criticalAlerts: 0,
    riskScore: 0,
    activeConnections: 0,
  },
  setMetrics: (metrics) => set({ metrics }),
  
  // Selected items for detailed view
  selectedProcess: null,
  selectedNetworkFlow: null,
  selectedAlert: null,
  setSelectedProcess: (process) => set({ selectedProcess: process }),
  setSelectedNetworkFlow: (flow) => set({ selectedNetworkFlow: flow }),
  setSelectedAlert: (alert) => set({ selectedAlert: alert }),
  
  // UI state
  sidebarOpen: true,
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  
  // Real-time updates
  lastUpdate: null,
  setLastUpdate: (timestamp) => set({ lastUpdate: timestamp }),
  
  // Helper functions
  getThreatsByLevel: () => {
    const { threatData } = get();
    const threats = [];
    
    Object.values(threatData).forEach(data => {
      if (data?.summary?.correlations) {
        threats.push(...data.summary.correlations);
      }
    });
    
    return {
      critical: threats.filter(t => t.severity === 'critical' || t.priority === 'critical').length,
      high: threats.filter(t => t.severity === 'high' || t.priority === 'high').length,
      medium: threats.filter(t => t.severity === 'medium' || t.priority === 'medium').length,
      low: threats.filter(t => t.severity === 'low' || t.priority === 'low').length,
    };
  },
  
  getRecentAlerts: () => {
    const { threatData } = get();
    const alerts = [];
    
    if (threatData.procmon?.alerts) {
      alerts.push(...threatData.procmon.alerts);
    }
    
    return alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  },
}));

export default useCyberStore;
