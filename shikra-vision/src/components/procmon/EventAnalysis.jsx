import React, { useState } from 'react';
import {
  DocumentTextIcon,
  CpuChipIcon,
  FolderIcon,
  Cog6ToothIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  CalendarIcon,
  ClockIcon,
  PlayIcon,
  StopIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts';

const EventAnalysis = ({ procmonData }) => {
  const [selectedEventType, setSelectedEventType] = useState('all');
  const events = procmonData?.events || [];
  const eventCounts = procmonData?.aggregations?.event_counts || {};
  const timelineData = procmonData?.aggregations?.timeline || [];

  // Filter events based on selected type
  const filteredEvents = selectedEventType === 'all' ? 
    events : 
    events.filter(event => event.event_class === selectedEventType);

  // Prepare event type distribution data
  const eventTypeData = Object.entries(eventCounts).map(([type, count]) => ({
    name: type.replace(/_/g, ' ').toUpperCase(),
    value: count,
    percentage: ((count / events.length) * 100).toFixed(1)
  }));

  // Color scheme for pie chart
  const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#F97316'];

  // Get event type icon
  const getEventIcon = (eventType) => {
    switch (eventType) {
      case 'process':
        return <CpuChipIcon className="h-5 w-5" />;
      case 'file':
        return <FolderIcon className="h-5 w-5" />;
      case 'registry':
        return <DocumentTextIcon className="h-5 w-5" />;
      case 'network':
        return <GlobeAltIcon className="h-5 w-5" />;
      default:
        return <Cog6ToothIcon className="h-5 w-5" />;
    }
  };

  // Get operation icon
  const getOperationIcon = (operation) => {
    switch (operation) {
      case 'Process and Thread Activity':
        return <PlayIcon className="h-4 w-4 text-green-500" />;
      case 'Process and Thread Activity - Process Start':
        return <PlayIcon className="h-4 w-4 text-green-500" />;
      case 'Process and Thread Activity - Process Exit':
        return <StopIcon className="h-4 w-4 text-red-500" />;
      case 'Registry':
        return <DocumentTextIcon className="h-4 w-4 text-blue-500" />;
      case 'File system':
        return <FolderIcon className="h-4 w-4 text-orange-500" />;
      case 'Network':
        return <GlobeAltIcon className="h-4 w-4 text-purple-500" />;
      default:
        return <ArrowPathIcon className="h-4 w-4 text-gray-500" />;
    }
  };

  // Get result color
  const getResultColor = (result) => {
    if (result === 'SUCCESS') return 'text-green-600 dark:text-green-400';
    if (result === 'BUFFER OVERFLOW' || result === 'ACCESS DENIED') return 'text-red-600 dark:text-red-400';
    if (result === 'NOT FOUND' || result === 'NAME NOT FOUND') return 'text-yellow-600 dark:text-yellow-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  return (
    <div className="space-y-6">
      {/* Event Statistics */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Event Type Distribution Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <DocumentTextIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Type Distribution</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={eventTypeData}
                cx="50%"
                cy="50%"
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
                label={({ name, percentage }) => `${name}: ${percentage}%`}
              >
                {eventTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Timeline Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ClockIcon className="h-6 w-6 text-green-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Timeline</h3>
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
              <Line type="monotone" dataKey="event_count" stroke="#3B82F6" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Event Type Filter and Counts */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <DocumentTextIcon className="h-6 w-6 text-purple-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Analysis</h3>
          </div>
          <select
            value={selectedEventType}
            onChange={(e) => setSelectedEventType(e.target.value)}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
          >
            <option value="all">All Events</option>
            <option value="process">Process Events</option>
            <option value="file">File Events</option>
            <option value="registry">Registry Events</option>
            <option value="network">Network Events</option>
          </select>
        </div>

        {/* Event Type Summary Cards */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-6">
          {Object.entries(eventCounts).map(([type, count]) => (
            <div 
              key={type}
              className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                selectedEventType === type 
                  ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-500' 
                  : 'bg-gray-50 dark:bg-gray-700 border-gray-200 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-600'
              }`}
              onClick={() => setSelectedEventType(type)}
            >
              <div className="flex items-center">
                <div className="text-blue-500">
                  {getEventIcon(type)}
                </div>
                <div className="ml-3">
                  <p className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                    {type.replace(/_/g, ' ')} Events
                  </p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {count.toLocaleString()}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Recent Events Table */}
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Process
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Operation
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Path/Detail
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Result
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {filteredEvents.slice(0, 50).map((event, index) => (
                <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white font-mono">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <CpuChipIcon className="h-4 w-4 text-blue-500 mr-2" />
                      <div>
                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                          {event.process_name || 'Unknown'}
                        </div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          PID: {event.pid || 'N/A'}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      {getOperationIcon(event.operation)}
                      <span className="ml-2 text-sm text-gray-900 dark:text-white">
                        {event.operation || 'Unknown'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs truncate">
                    {event.path || event.detail || 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`text-sm font-medium ${getResultColor(event.result)}`}>
                      {event.result || 'Unknown'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredEvents.length > 50 && (
          <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500 mr-2" />
              <span className="text-sm text-yellow-700 dark:text-yellow-300">
                Showing first 50 of {filteredEvents.length.toLocaleString()} {selectedEventType} events
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EventAnalysis;
