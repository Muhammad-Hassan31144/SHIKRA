import React, { useState } from 'react';
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ClockIcon,
  CpuChipIcon,
  FolderIcon,
  DocumentTextIcon,
  EyeIcon,
  FireIcon,
  XMarkIcon,
  CheckIcon
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';

const AlertDashboard = ({ procmonData }) => {
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [showDetails, setShowDetails] = useState({});
  
  const alerts = procmonData?.alerts || [];
  const alertMetrics = procmonData?.alert_metrics || {};
  
  // Filter alerts based on selections
  const filteredAlerts = alerts.filter(alert => {
    const severityMatch = selectedSeverity === 'all' || alert.severity === selectedSeverity;
    const categoryMatch = selectedCategory === 'all' || alert.category === selectedCategory;
    return severityMatch && categoryMatch;
  });

  // Group alerts by severity
  const alertsBySeverity = alerts.reduce((acc, alert) => {
    acc[alert.severity] = (acc[alert.severity] || 0) + 1;
    return acc;
  }, {});

  // Group alerts by category
  const alertsByCategory = alerts.reduce((acc, alert) => {
    acc[alert.category] = (acc[alert.category] || 0) + 1;
    return acc;
  }, {});

  // Prepare data for charts
  const severityData = Object.entries(alertsBySeverity).map(([severity, count]) => ({
    name: severity.toUpperCase(),
    value: count,
    color: getSeverityColor(severity)
  }));

  const categoryData = Object.entries(alertsByCategory).map(([category, count]) => ({
    name: category.replace(/_/g, ' ').toUpperCase(),
    value: count
  }));

  // Alert timeline data
  const timelineData = alertMetrics.timeline || [];

  function getSeverityColor(severity) {
    switch (severity) {
      case 'critical':
        return '#DC2626';
      case 'high':
        return '#EA580C';
      case 'medium':
        return '#D97706';
      case 'low':
        return '#65A30D';
      case 'info':
        return '#2563EB';
      default:
        return '#6B7280';
    }
  }

  function getSeverityIcon(severity) {
    switch (severity) {
      case 'critical':
        return <FireIcon className="h-5 w-5 text-red-600" />;
      case 'high':
        return <ExclamationTriangleIcon className="h-5 w-5 text-orange-600" />;
      case 'medium':
        return <ShieldExclamationIcon className="h-5 w-5 text-yellow-600" />;
      case 'low':
        return <EyeIcon className="h-5 w-5 text-blue-600" />;
      default:
        return <ExclamationTriangleIcon className="h-5 w-5 text-gray-600" />;
    }
  }

  function getCategoryIcon(category) {
    switch (category) {
      case 'process_anomaly':
        return <CpuChipIcon className="h-5 w-5" />;
      case 'file_anomaly':
        return <FolderIcon className="h-5 w-5" />;
      case 'registry_anomaly':
        return <DocumentTextIcon className="h-5 w-5" />;
      case 'suspicious_activity':
        return <ExclamationTriangleIcon className="h-5 w-5" />;
      default:
        return <ShieldExclamationIcon className="h-5 w-5" />;
    }
  }

  const toggleDetails = (alertId) => {
    setShowDetails(prev => ({
      ...prev,
      [alertId]: !prev[alertId]
    }));
  };

  return (
    <div className="space-y-6">
      {/* Alert Summary Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <FireIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Critical</p>
              <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                {alertsBySeverity.critical || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">High</p>
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {alertsBySeverity.high || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ShieldExclamationIcon className="h-8 w-8 text-yellow-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Medium</p>
              <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                {alertsBySeverity.medium || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <EyeIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Low</p>
              <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {alertsBySeverity.low || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-gray-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {alerts.length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Severity Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ExclamationTriangleIcon className="h-6 w-6 text-red-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Alert Severity Distribution</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill={(entry) => entry.color} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Alert Timeline */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Alert Timeline</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="timestamp" 
                tickFormatter={(value) => new Date(value).toLocaleTimeString()}
              />
              <YAxis />
              <Tooltip 
                labelFormatter={(value) => new Date(value).toLocaleString()}
              />
              <Legend />
              <Line type="monotone" dataKey="critical" stroke="#DC2626" strokeWidth={2} />
              <Line type="monotone" dataKey="high" stroke="#EA580C" strokeWidth={2} />
              <Line type="monotone" dataKey="medium" stroke="#D97706" strokeWidth={2} />
              <Line type="monotone" dataKey="low" stroke="#2563EB" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Alert Filters</h3>
          <div className="flex space-x-4">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Categories</option>
              <option value="process_anomaly">Process Anomaly</option>
              <option value="file_anomaly">File Anomaly</option>
              <option value="registry_anomaly">Registry Anomaly</option>
              <option value="suspicious_activity">Suspicious Activity</option>
            </select>
          </div>
        </div>

        <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </div>
      </div>

      {/* Alert List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Active Alerts</h3>
        </div>
        
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {filteredAlerts.length > 0 ? (
            filteredAlerts.map((alert, index) => (
              <div key={index} className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className="flex-shrink-0">
                      {getSeverityIcon(alert.severity)}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-2">
                        <h4 className="text-lg font-medium text-gray-900 dark:text-white">
                          {alert.title || 'Alert'}
                        </h4>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                          alert.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300' :
                          alert.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-300' :
                          alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300' :
                          alert.severity === 'low' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300' :
                          'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                        }`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                          {alert.category.replace(/_/g, ' ').toUpperCase()}
                        </span>
                      </div>
                      
                      <p className="text-gray-600 dark:text-gray-400 mb-3">
                        {alert.description || 'No description available'}
                      </p>
                      
                      <div className="flex items-center space-x-6 text-sm text-gray-500 dark:text-gray-400">
                        <div className="flex items-center">
                          <ClockIcon className="h-4 w-4 mr-1" />
                          {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'Unknown time'}
                        </div>
                        
                        {alert.process_name && (
                          <div className="flex items-center">
                            <CpuChipIcon className="h-4 w-4 mr-1" />
                            {alert.process_name} ({alert.pid || 'N/A'})
                          </div>
                        )}
                        
                        {alert.file_path && (
                          <div className="flex items-center">
                            <FolderIcon className="h-4 w-4 mr-1" />
                            <span className="truncate max-w-xs" title={alert.file_path}>
                              {alert.file_path}
                            </span>
                          </div>
                        )}
                      </div>

                      {showDetails[index] && alert.details && (
                        <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                          <h5 className="font-medium text-gray-900 dark:text-white mb-2">Alert Details</h5>
                          <div className="space-y-2 text-sm">
                            {Object.entries(alert.details).map(([key, value]) => (
                              <div key={key} className="flex justify-between">
                                <span className="text-gray-500 dark:text-gray-400 capitalize">
                                  {key.replace(/_/g, ' ')}:
                                </span>
                                <span className="text-gray-900 dark:text-white font-mono">
                                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2 ml-4">
                    {alert.details && (
                      <button
                        onClick={() => toggleDetails(index)}
                        className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                        title={showDetails[index] ? 'Hide details' : 'Show details'}
                      >
                        <EyeIcon className="h-5 w-5" />
                      </button>
                    )}
                    
                    <button
                      className="p-2 text-gray-400 hover:text-green-600 dark:hover:text-green-400"
                      title="Mark as resolved"
                    >
                      <CheckIcon className="h-5 w-5" />
                    </button>
                    
                    <button
                      className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                      title="Dismiss alert"
                    >
                      <XMarkIcon className="h-5 w-5" />
                    </button>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="p-6 text-center text-gray-500 dark:text-gray-400">
              <ShieldExclamationIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <p>No alerts match the current filters</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertDashboard;
