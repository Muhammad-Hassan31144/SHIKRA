import React, { useState } from 'react';
import {
  CalendarDaysIcon,
  ClockIcon,
  PlayIcon,
  StopIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ChevronRightIcon,
  ArrowRightIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  EyeIcon
} from '@heroicons/react/24/outline';

const TimelineAnalysis = ({ combinedData }) => {
  const [selectedTimeframe, setSelectedTimeframe] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [expandedEvent, setExpandedEvent] = useState(null);
  
  const summary = combinedData?.summary || {};
  const timeline = summary.timeline || {};
  const timelineData = timeline.events || [];

  // Parse and sort timeline events
  const parseTimeline = () => {
    return timelineData.map((event, index) => {
      const timestamp = new Date(event.timestamp);
      return {
        ...event,
        id: index,
        timestamp,
        timeString: timestamp.toLocaleTimeString(),
        dateString: timestamp.toLocaleDateString(),
        fullDateTime: timestamp.toLocaleString()
      };
    }).sort((a, b) => a.timestamp - b.timestamp);
  };

  const events = parseTimeline();

  // Filter events
  const getFilteredEvents = () => {
    let filtered = events;
    
    if (selectedSeverity !== 'all') {
      filtered = filtered.filter(event => event.severity === selectedSeverity);
    }
    
    if (selectedTimeframe !== 'all') {
      const now = new Date();
      const timeframes = {
        '1h': 60 * 60 * 1000,
        '6h': 6 * 60 * 60 * 1000,
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000
      };
      
      const cutoff = new Date(now.getTime() - timeframes[selectedTimeframe]);
      filtered = filtered.filter(event => event.timestamp >= cutoff);
    }
    
    return filtered;
  };

  const filteredEvents = getFilteredEvents();

  // Timeline statistics
  const getTimelineStats = () => {
    const severityCounts = events.reduce((acc, event) => {
      acc[event.severity] = (acc[event.severity] || 0) + 1;
      return acc;
    }, {});

    const sourceCounts = events.reduce((acc, event) => {
      acc[event.source] = (acc[event.source] || 0) + 1;
      return acc;
    }, {});

    const typeCounts = events.reduce((acc, event) => {
      acc[event.event_type] = (acc[event.event_type] || 0) + 1;
      return acc;
    }, {});

    return { severityCounts, sourceCounts, typeCounts };
  };

  const { severityCounts, sourceCounts, typeCounts } = getTimelineStats();

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-600 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800',
      high: 'text-orange-600 bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800',
      medium: 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800',
      low: 'text-blue-600 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800',
      info: 'text-gray-600 bg-gray-50 dark:bg-gray-700 border-gray-200 dark:border-gray-600'
    };
    return colors[severity] || colors.info;
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return XCircleIcon;
      case 'medium':
        return ExclamationTriangleIcon;
      case 'low':
      case 'info':
        return CheckCircleIcon;
      default:
        return ClockIcon;
    }
  };

  const getSourceColor = (source) => {
    const colors = {
      procmon: 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
      volatility: 'text-green-600 bg-green-50 dark:bg-green-900/20',
      pcap: 'text-purple-600 bg-purple-50 dark:bg-purple-900/20'
    };
    return colors[source] || 'text-gray-600 bg-gray-50 dark:bg-gray-700';
  };

  const formatEventType = (eventType) => {
    return eventType.split('_').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  return (
    <div className="space-y-6">
      {/* Timeline Summary Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <CalendarDaysIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Events</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {events.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Critical Events</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {severityCounts.critical || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ClockIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Time Span</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {timeline.duration || 'N/A'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <PlayIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">First Event</p>
              <p className="text-sm font-medium text-gray-900 dark:text-white">
                {timeline.first_event ? new Date(timeline.first_event).toLocaleString() : 'N/A'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Data Source Distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Event Sources</h3>
          <div className="space-y-3">
            {Object.entries(sourceCounts).map(([source, count]) => (
              <div key={source} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`w-3 h-3 rounded-full ${getSourceColor(source)} mr-2`}></div>
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize">
                    {source}
                  </span>
                </div>
                <span className="text-sm font-bold text-gray-900 dark:text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Breakdown</h3>
          <div className="space-y-3">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`w-3 h-3 rounded-full ${getSeverityColor(severity).split(' ')[0]} mr-2`}></div>
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize">
                    {severity}
                  </span>
                </div>
                <span className="text-sm font-bold text-gray-900 dark:text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Event Types</h3>
          <div className="space-y-3">
            {Object.entries(typeCounts).slice(0, 5).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  {formatEventType(type)}
                </span>
                <span className="text-sm font-bold text-gray-900 dark:text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Timeline Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex flex-col space-y-4 lg:flex-row lg:items-center lg:justify-between lg:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <FunnelIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Timeframe:</span>
            </div>
            <select
              value={selectedTimeframe}
              onChange={(e) => setSelectedTimeframe(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Time</option>
              <option value="1h">Last Hour</option>
              <option value="6h">Last 6 Hours</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
            </select>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Severity:</span>
            </div>
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
            
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredEvents.length} events
            </span>
          </div>
        </div>
      </div>

      {/* Timeline Events */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Timeline</h3>
        </div>
        
        <div className="p-6">
          {filteredEvents.length > 0 ? (
            <div className="space-y-4">
              {filteredEvents.map((event, index) => {
                const SeverityIcon = getSeverityIcon(event.severity);
                const isExpanded = expandedEvent === event.id;
                
                return (
                  <div
                    key={event.id}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden"
                  >
                    <div
                      className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700"
                      onClick={() => setExpandedEvent(isExpanded ? null : event.id)}
                    >
                      <div className="flex items-center space-x-4 flex-1">
                        <div className="flex items-center space-x-2">
                          <SeverityIcon className={`h-5 w-5 ${getSeverityColor(event.severity).split(' ')[0]}`} />
                          <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(event.severity)}`}>
                            {event.severity}
                          </span>
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2">
                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                              {formatEventType(event.event_type)}
                            </span>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSourceColor(event.source)}`}>
                              {event.source}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 truncate mt-1">
                            {event.description}
                          </p>
                        </div>
                        
                        <div className="text-right">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {event.timeString}
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            {event.dateString}
                          </p>
                        </div>
                      </div>
                      
                      <ChevronRightIcon 
                        className={`h-5 w-5 text-gray-400 ml-2 transition-transform ${
                          isExpanded ? 'transform rotate-90' : ''
                        }`}
                      />
                    </div>
                    
                    {isExpanded && (
                      <div className="border-t border-gray-200 dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-700">
                        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Event Details</h4>
                            <div className="space-y-2 text-sm">
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Full Timestamp:</span>
                                <span className="text-gray-900 dark:text-white font-mono">
                                  {event.fullDateTime}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Source:</span>
                                <span className="text-gray-900 dark:text-white">{event.source}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Event Type:</span>
                                <span className="text-gray-900 dark:text-white">{formatEventType(event.event_type)}</span>
                              </div>
                              {event.process_name && (
                                <div className="flex justify-between">
                                  <span className="text-gray-600 dark:text-gray-400">Process:</span>
                                  <span className="text-gray-900 dark:text-white font-mono">{event.process_name}</span>
                                </div>
                              )}
                            </div>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Description</h4>
                            <p className="text-sm text-gray-600 dark:text-gray-400">
                              {event.description}
                            </p>
                            {event.details && (
                              <div className="mt-3">
                                <h5 className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Additional Details:</h5>
                                <div className="bg-white dark:bg-gray-800 p-2 rounded border text-xs font-mono text-gray-600 dark:text-gray-400">
                                  {typeof event.details === 'object' ? JSON.stringify(event.details, null, 2) : event.details}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12">
              <CalendarDaysIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <p className="text-gray-500 dark:text-gray-400">
                No events found matching your criteria
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TimelineAnalysis;
