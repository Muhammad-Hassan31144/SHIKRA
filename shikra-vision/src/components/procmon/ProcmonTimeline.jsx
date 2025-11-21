import React, { useState } from 'react';
import {
  ClockIcon,
  PlayIcon,
  StopIcon,
  DocumentTextIcon,
  CpuChipIcon,
  FolderIcon,
  GlobeAltIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  ChevronLeftIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';

const ProcmonTimeline = ({ procmonData }) => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedEventTypes, setSelectedEventTypes] = useState(['all']);
  const [searchTerm, setSearchTerm] = useState('');
  
  const timeline = procmonData?.aggregations?.timeline || [];
  const events = procmonData?.events || [];
  const eventsPerPage = 50;

  // Filter events based on search and event types
  const filteredEvents = events.filter(event => {
    const matchesSearch = !searchTerm || 
      event.process_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.operation?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.path?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesType = selectedEventTypes.includes('all') || 
      selectedEventTypes.includes(event.event_class);
    
    return matchesSearch && matchesType;
  });

  // Paginate events
  const totalPages = Math.ceil(filteredEvents.length / eventsPerPage);
  const paginatedEvents = filteredEvents.slice(
    (currentPage - 1) * eventsPerPage,
    currentPage * eventsPerPage
  );

  // Process timeline data for different time ranges
  const getTimelineData = () => {
    const now = new Date();
    const timeRanges = {
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000
    };
    
    const cutoff = new Date(now.getTime() - timeRanges[selectedTimeRange]);
    return timeline.filter(item => new Date(item.timestamp) >= cutoff);
  };

  // Get event type icon
  const getEventIcon = (eventType, operation) => {
    if (operation?.includes('Process')) {
      if (operation.includes('Start')) {
        return <PlayIcon className="h-4 w-4 text-green-500" />;
      } else if (operation.includes('Exit')) {
        return <StopIcon className="h-4 w-4 text-red-500" />;
      }
      return <CpuChipIcon className="h-4 w-4 text-blue-500" />;
    }
    
    switch (eventType) {
      case 'process':
        return <CpuChipIcon className="h-4 w-4 text-blue-500" />;
      case 'file':
        return <FolderIcon className="h-4 w-4 text-orange-500" />;
      case 'registry':
        return <DocumentTextIcon className="h-4 w-4 text-purple-500" />;
      case 'network':
        return <GlobeAltIcon className="h-4 w-4 text-green-500" />;
      default:
        return <ArrowPathIcon className="h-4 w-4 text-gray-500" />;
    }
  };

  // Get result color
  const getResultColor = (result) => {
    if (result === 'SUCCESS') return 'text-green-600 dark:text-green-400';
    if (result?.includes('DENIED') || result?.includes('ERROR')) return 'text-red-600 dark:text-red-400';
    if (result?.includes('NOT FOUND')) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  // Handle event type filter change
  const handleEventTypeChange = (eventType) => {
    if (eventType === 'all') {
      setSelectedEventTypes(['all']);
    } else {
      const newTypes = selectedEventTypes.filter(type => type !== 'all');
      if (newTypes.includes(eventType)) {
        const filtered = newTypes.filter(type => type !== eventType);
        setSelectedEventTypes(filtered.length === 0 ? ['all'] : filtered);
      } else {
        setSelectedEventTypes([...newTypes, eventType]);
      }
    }
    setCurrentPage(1);
  };

  const timelineData = getTimelineData();

  return (
    <div className="space-y-6">
      {/* Timeline Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Activity Timeline</h3>
          </div>
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
          >
            <option value="15m">Last 15 minutes</option>
            <option value="1h">Last hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
          </select>
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
              formatter={(value, name) => [value.toLocaleString(), name]}
            />
            <Legend />
            <Line type="monotone" dataKey="event_count" stroke="#3B82F6" strokeWidth={2} name="Total Events" />
            <Line type="monotone" dataKey="process_events" stroke="#10B981" strokeWidth={2} name="Process Events" />
            <Line type="monotone" dataKey="file_events" stroke="#F59E0B" strokeWidth={2} name="File Events" />
            <Line type="monotone" dataKey="registry_events" stroke="#8B5CF6" strokeWidth={2} name="Registry Events" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Event Distribution Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <DocumentTextIcon className="h-6 w-6 text-green-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Distribution Over Time</h3>
        </div>
        
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={timelineData}>
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
            <Bar dataKey="process_events" stackId="a" fill="#3B82F6" name="Process" />
            <Bar dataKey="file_events" stackId="a" fill="#10B981" name="File" />
            <Bar dataKey="registry_events" stackId="a" fill="#F59E0B" name="Registry" />
            <Bar dataKey="network_events" stackId="a" fill="#8B5CF6" name="Network" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Event Filters and Search */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex flex-col space-y-4 lg:flex-row lg:items-center lg:justify-between lg:space-y-0">
          <div className="flex flex-wrap gap-2">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300 mr-2">Filter by type:</span>
            {['all', 'process', 'file', 'registry', 'network'].map(type => (
              <button
                key={type}
                onClick={() => handleEventTypeChange(type)}
                className={`px-3 py-1 rounded-full text-sm font-medium transition-colors ${
                  selectedEventTypes.includes(type)
                    ? 'bg-blue-500 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                {type.charAt(0).toUpperCase() + type.slice(1)}
              </button>
            ))}
          </div>
          
          <div className="flex items-center space-x-4">
            <input
              type="text"
              placeholder="Search events..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredEvents.length.toLocaleString()} events
            </span>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Timeline</h3>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Type
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
              {paginatedEvents.map((event, index) => (
                <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white font-mono">
                    <div>
                      <div>{new Date(event.timestamp).toLocaleTimeString()}</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {new Date(event.timestamp).toLocaleDateString()}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      {getEventIcon(event.event_class, event.operation)}
                      <span className="ml-2 text-sm text-gray-900 dark:text-white capitalize">
                        {event.event_class || 'Unknown'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {event.process_name || 'Unknown'}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        PID: {event.pid || 'N/A'}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs">
                    <div className="truncate" title={event.operation}>
                      {event.operation || 'Unknown'}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs">
                    <div className="truncate" title={event.path || event.detail}>
                      {event.path || event.detail || 'N/A'}
                    </div>
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

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-6 py-3 border-t border-gray-200 dark:border-gray-700">
            <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
              Showing {((currentPage - 1) * eventsPerPage) + 1} to {Math.min(currentPage * eventsPerPage, filteredEvents.length)} of {filteredEvents.length.toLocaleString()} events
            </div>
            
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
                className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeftIcon className="h-5 w-5" />
              </button>
              
              <span className="px-3 py-1 text-sm text-gray-700 dark:text-gray-300">
                Page {currentPage} of {totalPages}
              </span>
              
              <button
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
                className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRightIcon className="h-5 w-5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Summary Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Events/Hour</p>
              <p className="text-xl font-bold text-gray-900 dark:text-white">
                {timelineData.length > 0 ? 
                  Math.round(timelineData.reduce((sum, item) => sum + (item.event_count || 0), 0) / Math.max(timelineData.length, 1)).toLocaleString() : 
                  '0'
                }
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Process Events</p>
              <p className="text-xl font-bold text-gray-900 dark:text-white">
                {filteredEvents.filter(e => e.event_class === 'process').length.toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <FolderIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">File Events</p>
              <p className="text-xl font-bold text-gray-900 dark:text-white">
                {filteredEvents.filter(e => e.event_class === 'file').length.toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Errors</p>
              <p className="text-xl font-bold text-gray-900 dark:text-white">
                {filteredEvents.filter(e => e.result && !e.result.includes('SUCCESS')).length.toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProcmonTimeline;
