import React, { useState } from 'react';
import {
  ChartBarIcon,
  ClockIcon,
  DocumentTextIcon,
  FolderIcon,
  CpuChipIcon,
  GlobeAltIcon,
  ArrowTrendingUpIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, AreaChart, Area } from 'recharts';

const AggregationSummary = ({ procmonData }) => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const aggregations = procmonData?.aggregations || {};
  
  const eventCounts = aggregations.event_counts || {};
  const timeline = aggregations.timeline || [];
  const topProcesses = aggregations.top_processes || [];
  const topFiles = aggregations.top_files || [];
  const errorCounts = aggregations.error_counts || {};
  const userActivity = aggregations.user_activity || {};

  // Prepare data for charts
  const eventTypeData = Object.entries(eventCounts).map(([type, count]) => ({
    name: type.replace(/_/g, ' ').toUpperCase(),
    value: count,
    color: getEventTypeColor(type)
  }));

  const errorData = Object.entries(errorCounts).map(([error, count]) => ({
    name: error.replace(/_/g, ' '),
    value: count
  }));

  const processActivityData = topProcesses.slice(0, 10).map(process => ({
    name: process.process_name,
    events: process.event_count,
    files: process.file_operations || 0,
    registry: process.registry_operations || 0
  }));

  function getEventTypeColor(type) {
    const colors = {
      process: '#3B82F6',
      file: '#10B981',
      registry: '#F59E0B',
      network: '#EF4444',
      default: '#8B5CF6'
    };
    return colors[type] || colors.default;
  }

  const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#F97316'];

  return (
    <div className="space-y-6">
      {/* Summary Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Events</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {Object.values(eventCounts).reduce((sum, count) => sum + count, 0).toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Unique Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {topProcesses.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <FolderIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Files Accessed</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {topFiles.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Errors</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {Object.values(errorCounts).reduce((sum, count) => sum + count, 0).toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Event Type Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ChartBarIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Type Distribution</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={eventTypeData}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value.toLocaleString()}`}
              >
                {eventTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value) => value.toLocaleString()} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Timeline Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center">
              <ClockIcon className="h-6 w-6 text-green-500 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Activity Timeline</h3>
            </div>
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="15m">Last 15 minutes</option>
              <option value="1h">Last hour</option>
              <option value="6h">Last 6 hours</option>
              <option value="24h">Last 24 hours</option>
            </select>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="timestamp" 
                tickFormatter={(value) => new Date(value).toLocaleTimeString()}
              />
              <YAxis />
              <Tooltip 
                labelFormatter={(value) => new Date(value).toLocaleString()}
                formatter={(value) => [value.toLocaleString(), 'Events']}
              />
              <Area 
                type="monotone" 
                dataKey="event_count" 
                stroke="#3B82F6" 
                fill="#93C5FD" 
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Process Activity and Error Analysis */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top Processes */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ArrowTrendingUpIcon className="h-6 w-6 text-purple-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Most Active Processes</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={processActivityData} layout="horizontal">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="name" type="category" width={100} />
              <Tooltip formatter={(value) => value.toLocaleString()} />
              <Legend />
              <Bar dataKey="events" fill="#3B82F6" name="Total Events" />
              <Bar dataKey="files" fill="#10B981" name="File Ops" />
              <Bar dataKey="registry" fill="#F59E0B" name="Registry Ops" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Error Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ExclamationTriangleIcon className="h-6 w-6 text-red-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Error Distribution</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={errorData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="name" 
                angle={-45}
                textAnchor="end"
                height={80}
              />
              <YAxis />
              <Tooltip formatter={(value) => value.toLocaleString()} />
              <Bar dataKey="value" fill="#EF4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Detailed Tables */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top Processes Table */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <CpuChipIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Top Processes by Activity</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="text-left py-2 text-sm font-medium text-gray-500 dark:text-gray-400">Process</th>
                  <th className="text-right py-2 text-sm font-medium text-gray-500 dark:text-gray-400">Events</th>
                  <th className="text-right py-2 text-sm font-medium text-gray-500 dark:text-gray-400">Files</th>
                  <th className="text-right py-2 text-sm font-medium text-gray-500 dark:text-gray-400">Registry</th>
                </tr>
              </thead>
              <tbody>
                {topProcesses.slice(0, 10).map((process, index) => (
                  <tr key={index} className="border-b border-gray-100 dark:border-gray-700">
                    <td className="py-2 text-sm text-gray-900 dark:text-white">
                      <div>
                        <div className="font-medium">{process.process_name}</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">PID: {process.pid}</div>
                      </div>
                    </td>
                    <td className="py-2 text-sm text-gray-900 dark:text-white text-right">
                      {process.event_count.toLocaleString()}
                    </td>
                    <td className="py-2 text-sm text-gray-900 dark:text-white text-right">
                      {(process.file_operations || 0).toLocaleString()}
                    </td>
                    <td className="py-2 text-sm text-gray-900 dark:text-white text-right">
                      {(process.registry_operations || 0).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Files Table */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <FolderIcon className="h-6 w-6 text-green-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Most Accessed Files</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="text-left py-2 text-sm font-medium text-gray-500 dark:text-gray-400">File Path</th>
                  <th className="text-right py-2 text-sm font-medium text-gray-500 dark:text-gray-400">Accesses</th>
                  <th className="text-left py-2 text-sm font-medium text-gray-500 dark:text-gray-400">Operations</th>
                </tr>
              </thead>
              <tbody>
                {topFiles.slice(0, 10).map((file, index) => (
                  <tr key={index} className="border-b border-gray-100 dark:border-gray-700">
                    <td className="py-2 text-sm text-gray-900 dark:text-white">
                      <div className="max-w-xs truncate" title={file.path}>
                        {file.path}
                      </div>
                    </td>
                    <td className="py-2 text-sm text-gray-900 dark:text-white text-right">
                      {file.access_count.toLocaleString()}
                    </td>
                    <td className="py-2 text-sm text-gray-500 dark:text-gray-400">
                      <div className="flex flex-wrap gap-1">
                        {file.operations && file.operations.slice(0, 3).map((op, opIndex) => (
                          <span key={opIndex} className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 rounded">
                            {op}
                          </span>
                        ))}
                        {file.operations && file.operations.length > 3 && (
                          <span className="text-xs text-gray-400">+{file.operations.length - 3} more</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* User Activity Summary */}
      {Object.keys(userActivity).length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <GlobeAltIcon className="h-6 w-6 text-indigo-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">User Activity Summary</h3>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(userActivity).map(([user, activity]) => (
              <div key={user} className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-gray-900 dark:text-white">{user}</span>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {activity.total_events?.toLocaleString() || 0} events
                  </span>
                </div>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Process events:</span>
                    <span className="text-gray-900 dark:text-white">{activity.process_events || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">File events:</span>
                    <span className="text-gray-900 dark:text-white">{activity.file_events || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Registry events:</span>
                    <span className="text-gray-900 dark:text-white">{activity.registry_events || 0}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default AggregationSummary;
