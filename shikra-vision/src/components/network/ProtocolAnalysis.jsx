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
  Legend
} from 'recharts';
import { ChartBarIcon } from '@heroicons/react/24/outline';

const ProtocolAnalysis = ({ metadata, networkFlows }) => {
  if (!metadata?.statistics?.protocols && !networkFlows) return null;

  // Use metadata protocols if available, otherwise calculate from flows
  const protocolData = metadata?.statistics?.protocols 
    ? Object.entries(metadata.statistics.protocols).map(([protocol, count]) => ({
        name: protocol.toUpperCase(),
        value: count,
        color: getProtocolColor(protocol)
      }))
    : getProtocolDataFromFlows(networkFlows);

  function getProtocolColor(protocol) {
    const colors = {
      tcp: '#3B82F6',
      udp: '#10B981', 
      icmp: '#F59E0B',
      dns: '#8B5CF6',
      http: '#06B6D4',
      https: '#059669',
      smtp: '#DC2626',
      other: '#6B7280'
    };
    return colors[protocol.toLowerCase()] || '#6B7280';
  }

  function getProtocolDataFromFlows(flows) {
    if (!flows) return [];
    
    const protocolCounts = flows.reduce((acc, flow) => {
      const protocol = flow.protocol?.toLowerCase() || 'unknown';
      acc[protocol] = (acc[protocol] || 0) + 1;
      return acc;
    }, {});

    return Object.entries(protocolCounts).map(([protocol, count]) => ({
      name: protocol.toUpperCase(),
      value: count,
      color: getProtocolColor(protocol)
    }));
  }

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

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Protocol Distribution Pie Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ChartBarIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Protocol Distribution</h3>
        </div>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={protocolData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {protocolData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Protocol Count Bar Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Protocol Counts</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={protocolData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
              <XAxis 
                dataKey="name" 
                stroke="#6B7280"
                fontSize={12}
              />
              <YAxis stroke="#6B7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value">
                {protocolData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default ProtocolAnalysis;
