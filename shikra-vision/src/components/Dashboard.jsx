import { useEffect, useMemo } from 'react';
import useCyberStore from '../store/cyberStore';
import { sampleMemoryData, sampleNetworkData, sampleProcmonData } from '../utils/sampleData';
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ClockIcon,
  ChartBarIcon,
  GlobeAltIcon,
  CpuChipIcon,
  DocumentTextIcon,
  LinkIcon,
  ArrowTrendingUpIcon,
  CheckCircleIcon,
  XCircleIcon,
  EyeIcon,
  BugAntIcon
} from '@heroicons/react/24/outline';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, Area, AreaChart } from 'recharts';

const Dashboard = () => {
  const { 
    setThreatData, 
    setMetrics,
    threatData,
    currentView
  } = useCyberStore();

  const combinedData = threatData?.combinedAnalysis;

  // Calculate dynamic metrics from real data
  const metrics = useMemo(() => {
    if (!combinedData) return { totalThreats: 0, criticalAlerts: 0, riskScore: 0, activeConnections: 0 };

    const summary = combinedData.summary || {};
    const analysis = combinedData.analysis || {};
    
    // Count IOCs across all types
    const totalIOCs = Object.values(summary.iocs || {}).reduce((sum, iocs) => sum + (Array.isArray(iocs) ? iocs.length : 0), 0);
    
    // Count critical/high severity events
    const timelineEvents = summary.timeline?.events || [];
    const criticalEvents = timelineEvents.filter(e => e.severity === 'critical' || e.severity === 'high').length;
    
    // Get risk score
    const riskScore = summary.risk_score || 0;
    
    // Count correlations
    const totalCorrelations = summary.correlations?.length || 0;

    return {
      totalThreats: totalIOCs,
      criticalAlerts: criticalEvents,
      riskScore: riskScore,
      activeConnections: totalCorrelations
    };
  }, [combinedData]);

  // Prepare chart data
  const chartData = useMemo(() => {
    if (!combinedData) return { severityData: [], sourceData: [], timelineData: [], mitreData: [] };

    const summary = combinedData.summary || {};
    const timelineEvents = summary.timeline?.events || [];
    
    // Severity distribution
    const severityCounts = timelineEvents.reduce((acc, event) => {
      acc[event.severity] = (acc[event.severity] || 0) + 1;
      return acc;
    }, {});
    
    const severityData = Object.entries(severityCounts).map(([name, value]) => ({ name, value }));

    // Source distribution
    const sourceCounts = timelineEvents.reduce((acc, event) => {
      acc[event.source] = (acc[event.source] || 0) + 1;
      return acc;
    }, {});
    
    const sourceData = Object.entries(sourceCounts).map(([name, value]) => ({ name, value }));

    // Timeline data (events over time - simplified hourly grouping)
    const timelineData = timelineEvents.slice(0, 10).map((event, index) => ({
      time: new Date(event.timestamp).toLocaleTimeString(),
      events: timelineEvents.slice(0, index + 1).length,
      severity: event.severity
    }));

    // MITRE technique distribution
    const mitreTechniques = summary.mitre_techniques || [];
    const tacticCounts = mitreTechniques.reduce((acc, technique) => {
      acc[technique.tactic] = (acc[technique.tactic] || 0) + 1;
      return acc;
    }, {});
    
    const mitreData = Object.entries(tacticCounts).map(([name, value]) => ({ name, value }));

    return { severityData, sourceData, timelineData, mitreData };
  }, [combinedData]);

  useEffect(() => {
    // Load sample data on component mount
    setThreatData('memory', sampleMemoryData);
    setThreatData('network', sampleNetworkData);
    setThreatData('procmon', sampleProcmonData);
    
    // Set calculated metrics
    setMetrics(metrics);
  }, [setThreatData, setMetrics, metrics]);

  const COLORS = ['#EF4444', '#F97316', '#F59E0B', '#3B82F6', '#10B981', '#8B5CF6'];

  const getRiskLevelColor = (score) => {
    if (score >= 8) return 'text-red-600 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
    if (score >= 6) return 'text-orange-600 bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
    if (score >= 4) return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
    return 'text-green-600 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
  };

  const getRiskLevelText = (score) => {
    if (score >= 8) return 'Critical';
    if (score >= 6) return 'High';
    if (score >= 4) return 'Medium';
    return 'Low';
  };

  const formatTacticName = (tactic) => {
    return tactic.split('-').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  if (!combinedData) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading threat intelligence data...</p>
        </div>
      </div>
    );
  }

  const summary = combinedData.summary || {};
  const analysis = combinedData.analysis || {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Cybersecurity Threat Intelligence Overview
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Comprehensive analysis from {combinedData.meta?.available_reports?.length || 0} data sources
            </p>
          </div>
          <div className={`px-4 py-2 rounded-lg border ${getRiskLevelColor(summary.risk_score || 0)}`}>
            <div className="flex items-center space-x-2">
              <ShieldExclamationIcon className="h-6 w-6" />
              <div>
                <p className="text-sm font-medium">Overall Risk</p>
                <p className="text-lg font-bold">{getRiskLevelText(summary.risk_score || 0)}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total IOCs</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {metrics.totalThreats}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <ClockIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Critical Events</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {metrics.criticalAlerts}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <LinkIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Correlations</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {metrics.activeConnections}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <BugAntIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">MITRE Techniques</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {summary.mitre_techniques?.length || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Data Source Status */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Data Source Analysis</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {combinedData.meta?.available_reports?.map(source => {
            const sourceRisk = combinedData.meta?.individual_risk_scores?.[source];
            return (
              <div key={source} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center space-x-3">
                  {source === 'procmon' && <DocumentTextIcon className="h-6 w-6 text-blue-500" />}
                  {source === 'memory' && <CpuChipIcon className="h-6 w-6 text-green-500" />}
                  {source === 'network' && <GlobeAltIcon className="h-6 w-6 text-purple-500" />}
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white capitalize">{source}</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">Data Available</p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircleIcon className="h-5 w-5 text-green-500" />
                  {sourceRisk && (
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskLevelColor(sourceRisk)}`}>
                      {sourceRisk.toFixed(1)}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Event Severity Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Event Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData.severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {chartData.severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Timeline */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Attack Timeline</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData.timelineData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Area type="monotone" dataKey="events" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Data Source Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Events by Data Source</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData.sourceData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#10B981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* MITRE ATT&CK Tactics */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">MITRE ATT&CK Tactics</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData.mitreData} layout="horizontal">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" width={100} tickFormatter={formatTacticName} />
                <Tooltip formatter={(value, name) => [value, 'Techniques']} />
                <Bar dataKey="value" fill="#8B5CF6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Key Correlations and Recent Events */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* High-Priority Correlations */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Critical Correlations</h3>
          <div className="space-y-4">
            {summary.correlations?.slice(0, 5).map((correlation, index) => (
              <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <LinkIcon className="h-5 w-5 text-blue-500 mt-0.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {correlation.type}
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400 truncate">
                    {correlation.description}
                  </p>
                  <div className="flex items-center mt-1 space-x-2">
                    {correlation.sources?.map(source => (
                      <span key={source} className="px-2 py-1 bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200 text-xs rounded">
                        {source}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Critical Events */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Critical Events</h3>
          <div className="space-y-4">
            {summary.timeline?.events?.filter(e => e.severity === 'critical' || e.severity === 'high').slice(0, 5).map((event, index) => (
              <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <ExclamationTriangleIcon className={`h-5 w-5 mt-0.5 flex-shrink-0 ${
                  event.severity === 'critical' ? 'text-red-500' : 'text-orange-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {event.event_type?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </p>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      event.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200' :
                      'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-200'
                    }`}>
                      {event.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    {event.description}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    {new Date(event.timestamp).toLocaleString()} • {event.source}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Analysis Summary</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {Object.values(summary.iocs || {}).reduce((sum, iocs) => sum + (Array.isArray(iocs) ? iocs.length : 0), 0)}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Total IOCs</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-green-600 dark:text-green-400">
              {summary.timeline?.events?.length || 0}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Timeline Events</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-purple-600 dark:text-purple-400">
              {summary.mitre_techniques?.length || 0}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">MITRE Techniques</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {summary.correlations?.length || 0}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Cross-Source Correlations</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
