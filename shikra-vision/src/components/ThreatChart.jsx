import React from 'react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import useCyberStore from '../store/cyberStore';

// Sample threat data over time for visualization
const threatTimelineData = [
  { time: '00:00', threats: 12, critical: 2, high: 4, medium: 6 },
  { time: '04:00', threats: 18, critical: 3, high: 7, medium: 8 },
  { time: '08:00', threats: 25, critical: 5, high: 10, medium: 10 },
  { time: '12:00', threats: 31, critical: 7, high: 12, medium: 12 },
  { time: '16:00', threats: 28, critical: 6, high: 11, medium: 11 },
  { time: '20:00', threats: 22, critical: 4, high: 8, medium: 10 },
  { time: '24:00', threats: 15, critical: 3, high: 5, medium: 7 },
];

const networkTrafficData = [
  { name: 'HTTP', value: 45, color: '#3B82F6' },
  { name: 'HTTPS', value: 30, color: '#10B981' },
  { name: 'DNS', value: 15, color: '#F59E0B' },
  { name: 'Other', value: 10, color: '#EF4444' },
];

const processActivityData = [
  { process: 'chrome.exe', cpu: 25, memory: 512, threats: 2 },
  { process: 'explorer.exe', cpu: 15, memory: 256, threats: 0 },
  { process: 'svchost.exe', cpu: 35, memory: 128, threats: 5 },
  { process: 'winlogon.exe', cpu: 10, memory: 64, threats: 1 },
  { process: 'lsass.exe', cpu: 20, memory: 89, threats: 3 },
  { process: 'csrss.exe', cpu: 12, memory: 45, threats: 0 },
];

// Custom tooltip
const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="p-3 rounded-lg shadow-lg border bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-600 text-gray-900 dark:text-white">
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

export const ThreatTimelineChart = () => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Threat Activity Timeline</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">24-hour threat detection patterns</p>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={threatTimelineData}>
            <defs>
              <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0.1}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
            <XAxis 
              dataKey="time" 
              stroke="#6B7280"
              fontSize={12}
            />
            <YAxis 
              stroke="#6B7280"
              fontSize={12}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            <Area
              type="monotone"
              dataKey="threats"
              stroke="#EF4444"
              fillOpacity={1}
              fill="url(#threatGradient)"
              name="Total Threats"
            />
            <Line
              type="monotone"
              dataKey="critical"
              stroke="#DC2626"
              strokeWidth={2}
              name="Critical"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export const NetworkTrafficChart = () => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Network Traffic Distribution</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">Protocol usage breakdown</p>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={networkTrafficData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              outerRadius={100}
              fill="#8884d8"
              dataKey="value"
            >
              {networkTrafficData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export const ProcessActivityChart = () => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Process Resource Usage</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">CPU and Memory consumption by process</p>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={processActivityData} layout="horizontal">
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
            <XAxis 
              type="number"
              stroke="#6B7280"
              fontSize={12}
            />
            <YAxis 
              type="category"
              dataKey="process"
              stroke="#6B7280"
              fontSize={11}
              width={100}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            <Bar dataKey="cpu" fill="#3B82F6" name="CPU %" />
            <Bar dataKey="memory" fill="#10B981" name="Memory (MB)" />
            <Bar dataKey="threats" fill="#EF4444" name="Threats" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export const ThreatSeverityChart = () => {
  const { getThreatsByLevel } = useCyberStore();
  const threatLevels = getThreatsByLevel();
  
  const severityData = [
    { name: 'Critical', value: threatLevels.critical || 5, color: '#DC2626' },
    { name: 'High', value: threatLevels.high || 8, color: '#EA580C' },
    { name: 'Medium', value: threatLevels.medium || 12, color: '#D97706' },
    { name: 'Low', value: threatLevels.low || 7, color: '#65A30D' },
  ];
  
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Threat Severity Distribution</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">Current threat landscape by severity</p>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={severityData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
            <XAxis 
              dataKey="name"
              stroke="#6B7280"
              fontSize={12}
            />
            <YAxis 
              stroke="#6B7280"
              fontSize={12}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="value" fill={(entry) => entry.color} name="Count">
              {severityData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
