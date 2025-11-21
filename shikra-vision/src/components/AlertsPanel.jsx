import React from 'react';
import useCyberStore from '../store/cyberStore';
import { formatTimestamp } from '../utils/sampleData';
import { 
  BellIcon, 
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  InformationCircleIcon 
} from '@heroicons/react/24/outline';

const AlertsPanel = () => {
  const { threatData, getRecentAlerts } = useCyberStore();
  const alerts = getRecentAlerts();

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-600 dark:text-red-400" />;
      case 'high':
        return <ShieldExclamationIcon className="h-5 w-5 text-orange-600 dark:text-orange-400" />;
      case 'medium':
        return <InformationCircleIcon className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />;
    }
  };

  const getSeverityBadge = (severity) => {
    const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
    switch (severity) {
      case 'critical':
        return `${baseClasses} bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 animate-pulse`;
      case 'high':
        return `${baseClasses} bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200`;
      case 'medium':
        return `${baseClasses} bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200`;
      default:
        return `${baseClasses} bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200`;
    }
  };

  // Add some sample alerts if none exist
  const sampleAlerts = alerts.length === 0 ? [
    {
      id: 'alert_sample_1',
      timestamp: new Date().toISOString(),
      severity: 'critical',
      title: 'Malware Process Detected',
      description: 'Suspicious executable malicious.exe detected with C2 communication patterns',
      recommended_actions: ['isolate_host', 'collect_memory_dump']
    },
    {
      id: 'alert_sample_2',
      timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      severity: 'high',
      title: 'Suspicious Network Traffic',
      description: 'Unusual beaconing pattern detected to external IP 185.220.101.45',
      recommended_actions: ['block_c2_traffic', 'monitor_connections']
    },
    {
      id: 'alert_sample_3',
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      severity: 'medium',
      title: 'Registry Persistence',
      description: 'New autorun registry entry detected for suspicious executable',
      recommended_actions: ['remove_persistence', 'scan_registry']
    }
  ] : alerts;

  return (
    <div className="bg-white dark:bg-gray-800 shadow-sm border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="px-4 py-5 sm:p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
            Recent Alerts
          </h3>
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {sampleAlerts.filter(a => a.severity === 'critical').length} Critical
            </span>
            <BellIcon className="h-5 w-5 text-gray-400 dark:text-gray-500" />
          </div>
        </div>

        <div className="space-y-4 max-h-96 overflow-y-auto">
          {sampleAlerts.slice(0, 10).map((alert, index) => (
            <div
              key={alert.id || index}
              className={`p-4 border rounded-lg hover:shadow-md transition-shadow cursor-pointer ${
                alert.severity === 'critical' ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' :
                alert.severity === 'high' ? 'border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-900/20' :
                alert.severity === 'medium' ? 'border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20' :
                'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20'
              }`}
            >
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 mt-0.5">
                  {getSeverityIcon(alert.severity)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                      {alert.title}
                    </p>
                    <span className={getSeverityBadge(alert.severity)}>
                      {alert.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                    {alert.description}
                  </p>
                  <div className="flex items-center justify-between mt-3">
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {formatTimestamp(alert.timestamp)}
                    </p>
                    {alert.recommended_actions && (
                      <div className="flex flex-wrap gap-1">
                        {alert.recommended_actions.slice(0, 2).map((action, actionIndex) => (
                          <span
                            key={actionIndex}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
                          >
                            {action.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {sampleAlerts.length === 0 && (
          <div className="text-center py-8">
            <BellIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No alerts</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Security alerts will appear here when threats are detected.
            </p>
          </div>
        )}

        {/* Alert Summary */}
        {sampleAlerts.length > 0 && (
          <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Alert Summary</h4>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Critical:</span>
                <span className="font-medium text-red-600 dark:text-red-400">
                  {sampleAlerts.filter(a => a.severity === 'critical').length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">High:</span>
                <span className="font-medium text-orange-600 dark:text-orange-400">
                  {sampleAlerts.filter(a => a.severity === 'high').length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Medium:</span>
                <span className="font-medium text-yellow-600">
                  {sampleAlerts.filter(a => a.severity === 'medium').length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Low:</span>
                <span className="font-medium text-blue-600">
                  {sampleAlerts.filter(a => a.severity === 'low').length}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="mt-4 flex space-x-2">
          <button className="flex-1 bg-red-600 text-white text-sm px-3 py-2 rounded-md hover:bg-red-700 transition-colors">
            Isolate Host
          </button>
          <button className="flex-1 bg-orange-600 text-white text-sm px-3 py-2 rounded-md hover:bg-orange-700 transition-colors">
            Block IPs
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlertsPanel;
