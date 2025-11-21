import React from 'react';
import { 
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';
import { 
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  QuestionMarkCircleIcon
} from '@heroicons/react/24/outline';

const ThreatIntelligence = ({ networkFlows, dnsAnalysis, httpAnalysis }) => {
  if (!networkFlows && !dnsAnalysis && !httpAnalysis) return null;

  // Calculate reputation statistics from network flows
  const getReputationData = () => {
    if (!networkFlows) return [];
    
    const reputationCounts = networkFlows.reduce((acc, flow) => {
      const reputation = flow.threat_intel?.dst_reputation || 'unknown';
      acc[reputation] = (acc[reputation] || 0) + 1;
      return acc;
    }, {});

    const colors = {
      malicious: '#DC2626',
      suspicious: '#EA580C', 
      clean: '#65A30D',
      unknown: '#6B7280'
    };

    return Object.entries(reputationCounts).map(([reputation, count]) => ({
      name: reputation.charAt(0).toUpperCase() + reputation.slice(1),
      value: count,
      color: colors[reputation] || '#6B7280'
    }));
  };

  // Calculate threat categories
  const getThreatCategories = () => {
    if (!networkFlows) return [];
    
    const categories = networkFlows.reduce((acc, flow) => {
      const cats = flow.threat_intel?.dst_categories || [];
      cats.forEach(cat => {
        acc[cat] = (acc[cat] || 0) + 1;
      });
      return acc;
    }, {});

    return Object.entries(categories)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 8)
      .map(([category, count]) => ({
        category: category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        count,
        severity: getSeverityScore(category)
      }));
  };

  // Calculate confidence distribution
  const getConfidenceData = () => {
    if (!networkFlows) return [];
    
    const ranges = {
      'Very High (90-100%)': 0,
      'High (80-89%)': 0,
      'Medium (70-79%)': 0,
      'Low (60-69%)': 0,
      'Very Low (<60%)': 0
    };

    networkFlows.forEach(flow => {
      const confidence = flow.threat_intel?.confidence;
      if (confidence >= 0.9) ranges['Very High (90-100%)']++;
      else if (confidence >= 0.8) ranges['High (80-89%)']++;
      else if (confidence >= 0.7) ranges['Medium (70-79%)']++;
      else if (confidence >= 0.6) ranges['Low (60-69%)']++;
      else if (confidence !== undefined) ranges['Very Low (<60%)']++;
    });

    return Object.entries(ranges).map(([range, count]) => ({
      range,
      count
    }));
  };

  function getSeverityScore(category) {
    const scores = {
      'c2': 5,
      'malware': 5,
      'botnet': 5,
      'backdoor': 4,
      'trojan': 4,
      'suspicious': 3,
      'proxy': 2,
      'unknown': 1
    };
    return scores[category.toLowerCase()] || 1;
  }

  const reputationData = getReputationData();
  const threatCategories = getThreatCategories();
  const confidenceData = getConfidenceData();

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className='p-3 rounded-lg shadow-lg border 
            dark:bg-gray-800 dark:border-gray-600 dark:text-white
            bg-white border-gray-200 text-gray-900'
        >
          <p className="font-medium">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }} className="text-sm">
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  const getReputationIcon = (reputation) => {
    switch (reputation.toLowerCase()) {
      case 'malicious':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
      case 'suspicious':
        return <ShieldExclamationIcon className="h-5 w-5 text-orange-500" />;
      case 'clean':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      default:
        return <QuestionMarkCircleIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Threat Intelligence Overview */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="flex items-center mb-4">
          <ShieldExclamationIcon className="h-6 w-6 text-red-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Threat Intelligence Overview</h3>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {reputationData.map((item) => (
            <div key={item.name} className="text-center">
              <div className="flex items-center justify-center mb-2">
                {getReputationIcon(item.name)}
              </div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">{item.value}</div>
              <div className="text-sm text-gray-500 dark:text-gray-400">{item.name}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Reputation Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Reputation Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={reputationData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {reputationData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Confidence Levels */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Confidence Levels</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={confidenceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                <XAxis 
                  dataKey="range" 
                  stroke="#6B7280"
                  fontSize={10}
                  angle={-45}
                  textAnchor="end"
                  height={80}
                />
                <YAxis stroke="#6B7280" fontSize={12} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Threat Categories */}
      {threatCategories.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top Threat Categories</h3>
          <div className="space-y-3">
            {threatCategories.map((category, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center">
                  <div className={`w-3 h-3 rounded-full mr-3 ${
                    category.severity >= 4 ? 'bg-red-500' : 
                    category.severity >= 3 ? 'bg-orange-500' : 
                    'bg-yellow-500'
                  }`}></div>
                  <span className="text-sm font-medium text-gray-900 dark:text-white">
                    {category.category}
                  </span>
                </div>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {category.count} occurrences
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
