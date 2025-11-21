import React from 'react';
import useCyberStore from '../store/cyberStore';
import { 
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ChartBarIcon,
  GlobeAltIcon
} from '@heroicons/react/24/outline';

const MetricCard = ({ title, value, subtitle, icon: Icon, color, trend }) => (
  <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm dark:shadow-gray-700/30 rounded-lg border border-gray-200 dark:border-gray-700">
    <div className="p-5">
      <div className="flex items-center">
        <div className="flex-shrink-0">
          <Icon className={`h-6 w-6 ${color}`} />
        </div>
        <div className="ml-5 w-0 flex-1">
          <dl>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
              {title}
            </dt>
            <dd className="text-lg font-medium text-gray-900 dark:text-white">
              {value}
            </dd>
            {subtitle && (
              <dd className="text-sm text-gray-500 dark:text-gray-400">
                {subtitle}
              </dd>
            )}
          </dl>
        </div>
        {trend && (
          <div className={`ml-2 flex items-center text-sm ${
            trend > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'
          }`}>
            <span>{trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%</span>
          </div>
        )}
      </div>
    </div>
  </div>
);

const MetricCards = () => {
  const { metrics, getThreatsByLevel } = useCyberStore();
  const threatLevels = getThreatsByLevel();

  const getRiskScoreColor = (score) => {
    if (score >= 8) return 'text-red-600';
    if (score >= 6) return 'text-orange-600';
    if (score >= 4) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getRiskScoreLabel = (score) => {
    if (score >= 8) return 'Critical Risk';
    if (score >= 6) return 'High Risk';
    if (score >= 4) return 'Medium Risk';
    return 'Low Risk';
  };

  return (
    <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard
        title="Risk Score"
        value={metrics.riskScore.toFixed(1)}
        subtitle={getRiskScoreLabel(metrics.riskScore)}
        icon={ChartBarIcon}
        color={getRiskScoreColor(metrics.riskScore)}
        trend={2.3}
      />
      
      <MetricCard
        title="Critical Alerts"
        value={metrics.criticalAlerts}
        subtitle={`${threatLevels.high + threatLevels.critical} total high/critical`}
        icon={ExclamationTriangleIcon}
        color="text-red-600"
        trend={12}
      />
      
      <MetricCard
        title="Total Threats"
        value={metrics.totalThreats}
        subtitle={`${threatLevels.medium + threatLevels.low} low/medium severity`}
        icon={ShieldExclamationIcon}
        color="text-orange-600"
        trend={-5}
      />
      
      <MetricCard
        title="Active Connections"
        value={metrics.activeConnections}
        subtitle="Network flows monitored"
        icon={GlobeAltIcon}
        color="text-blue-600"
        trend={8}
      />
    </div>
  );
};

export default MetricCards;
