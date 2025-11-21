import React, { useState } from 'react';
import {
  ClockIcon,
  PlayIcon,
  PauseIcon,
  ForwardIcon,
  BackwardIcon,
  CalendarDaysIcon,
  ExclamationTriangleIcon,
  ChevronRightIcon,
  ArrowRightIcon,
  EyeIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';

const AttackTimeline = ({ combinedData }) => {
  const [selectedPhase, setSelectedPhase] = useState('all');
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  
  const analysis = combinedData?.analysis || {};
  const attackTimeline = analysis.attack_timeline || {};
  
  const phases = attackTimeline.phases || [];
  const events = attackTimeline.events || [];
  const killChain = attackTimeline.kill_chain || [];

  // Prepare timeline data for visualization
  const prepareTimelineData = () => {
    const sortedEvents = events
      .map(event => ({
        ...event,
        timestamp: new Date(event.timestamp),
        timeValue: new Date(event.timestamp).getTime()
      }))
      .sort((a, b) => a.timestamp - b.timestamp);

    // Create cumulative event count for chart
    return sortedEvents.map((event, index) => ({
      ...event,
      cumulativeEvents: index + 1,
      timeLabel: event.timestamp.toLocaleTimeString()
    }));
  };

  const timelineData = prepareTimelineData();

  // Prepare phase distribution data
  const preparePhaseData = () => {
    const phaseCounts = phases.reduce((acc, phase) => {
      acc[phase.name] = (acc[phase.name] || 0) + (phase.events?.length || 0);
      return acc;
    }, {});
    
    return Object.entries(phaseCounts).map(([name, count]) => ({ name, count }));
  };

  const phaseData = preparePhaseData();

  // Filter events by phase
  const getFilteredEvents = () => {
    if (selectedPhase === 'all') return timelineData;
    
    const phase = phases.find(p => p.name === selectedPhase);
    if (!phase || !phase.events) return [];
    
    return timelineData.filter(event => 
      phase.events.some(phaseEvent => phaseEvent.id === event.id)
    );
  };

  const filteredEvents = getFilteredEvents();

  // Get phase color
  const getPhaseColor = (phaseName) => {
    const colors = {
      'reconnaissance': 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800',
      'initial-access': 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800',
      'execution': 'bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800',
      'persistence': 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800',
      'privilege-escalation': 'bg-pink-50 dark:bg-pink-900/20 text-pink-700 dark:text-pink-300 border-pink-200 dark:border-pink-800',
      'defense-evasion': 'bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800',
      'credential-access': 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-300 border-indigo-200 dark:border-indigo-800',
      'discovery': 'bg-cyan-50 dark:bg-cyan-900/20 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800',
      'lateral-movement': 'bg-teal-50 dark:bg-teal-900/20 text-teal-700 dark:text-teal-300 border-teal-200 dark:border-teal-800',
      'collection': 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800',
      'command-and-control': 'bg-lime-50 dark:bg-lime-900/20 text-lime-700 dark:text-lime-300 border-lime-200 dark:border-lime-800',
      'exfiltration': 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800',
      'impact': 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'
    };
    return colors[phaseName.toLowerCase()] || 'bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-600';
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'text-red-500';
      case 'medium':
        return 'text-yellow-500';
      case 'low':
      case 'info':
        return 'text-blue-500';
      default:
        return 'text-gray-500';
    }
  };

  const formatPhaseName = (name) => {
    return name.split('-').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  const formatDuration = (startTime, endTime) => {
    if (!startTime || !endTime) return 'Unknown';
    const start = new Date(startTime);
    const end = new Date(endTime);
    const diff = end - start;
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  return (
    <div className="space-y-6">
      {/* Attack Timeline Overview */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ClockIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Duration</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {attackTimeline.total_duration || 'Unknown'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <PlayIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Attack Phases</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {phases.length}
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
                {events.filter(e => e.severity === 'critical').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <CalendarDaysIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">First Event</p>
              <p className="text-sm font-medium text-gray-900 dark:text-white">
                {attackTimeline.start_time ? new Date(attackTimeline.start_time).toLocaleString() : 'Unknown'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Progression Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Attack Progression</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="timeLabel" />
              <YAxis />
              <Tooltip 
                labelFormatter={(label) => `Time: ${label}`}
                formatter={(value) => [`${value} events`, 'Cumulative Events']}
              />
              <Area 
                type="monotone" 
                dataKey="cumulativeEvents" 
                stroke="#3B82F6" 
                fill="#3B82F6" 
                fillOpacity={0.3}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Kill Chain Phases */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">Cyber Kill Chain Progression</h3>
        
        {/* Phase Filter */}
        <div className="mb-6">
          <div className="flex items-center space-x-4">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filter by phase:</span>
            <select
              value={selectedPhase}
              onChange={(e) => setSelectedPhase(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Phases</option>
              {phases.map(phase => (
                <option key={phase.name} value={phase.name}>{formatPhaseName(phase.name)}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Kill Chain Visual */}
        <div className="space-y-4">
          {killChain.map((chainStep, index) => {
            const phase = phases.find(p => p.name === chainStep.phase);
            const isActive = selectedPhase === 'all' || selectedPhase === chainStep.phase;
            
            return (
              <div key={index} className={`relative ${!isActive ? 'opacity-50' : ''}`}>
                <div className="flex items-center">
                  {/* Step Number */}
                  <div className="flex-shrink-0 w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-medium">
                    {index + 1}
                  </div>
                  
                  {/* Phase Info */}
                  <div className="ml-4 flex-1">
                    <div className={`p-4 rounded-lg border ${getPhaseColor(chainStep.phase)}`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-medium">{formatPhaseName(chainStep.phase)}</h4>
                          <p className="text-xs mt-1 opacity-75">{chainStep.description}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-xs">
                            {formatDuration(chainStep.start_time, chainStep.end_time)}
                          </p>
                          <p className="text-xs opacity-75">
                            {phase?.events?.length || 0} events
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Arrow */}
                  {index < killChain.length - 1 && (
                    <div className="absolute left-4 top-8 w-0.5 h-8 bg-gray-300 dark:bg-gray-600"></div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Phase Details */}
      <div className="space-y-6">
        {phases.map((phase, phaseIndex) => {
          if (selectedPhase !== 'all' && selectedPhase !== phase.name) return null;
          
          return (
            <div key={phaseIndex} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mr-3">
                      {formatPhaseName(phase.name)}
                    </h3>
                    <span className={`px-2 py-1 rounded text-xs font-medium border ${getPhaseColor(phase.name)}`}>
                      {phase.events?.length || 0} events
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    Duration: {formatDuration(phase.start_time, phase.end_time)}
                  </div>
                </div>
                {phase.description && (
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">{phase.description}</p>
                )}
              </div>
              
              <div className="p-6">
                {phase.events && phase.events.length > 0 ? (
                  <div className="space-y-3">
                    {phase.events.map((event, eventIndex) => (
                      <div key={eventIndex} className="flex items-center space-x-4 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div className="flex-shrink-0">
                          <ClockIcon className={`h-5 w-5 ${getSeverityIcon(event.severity)}`} />
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2">
                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                              {event.event_type || 'Unknown Event'}
                            </span>
                            {event.severity && (
                              <span className={`px-2 py-1 rounded text-xs font-medium ${
                                event.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200' :
                                event.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-200' :
                                event.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200' :
                                'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200'
                              }`}>
                                {event.severity}
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 truncate mt-1">
                            {event.description || 'No description available'}
                          </p>
                        </div>
                        
                        <div className="text-right">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'Unknown'}
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            {event.source || 'Unknown source'}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <ClockIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
                    <p className="text-gray-500 dark:text-gray-400">No events found in this phase</p>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Timeline Events List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Complete Event Timeline ({filteredEvents.length} events)
          </h3>
        </div>
        
        <div className="p-6">
          {filteredEvents.length > 0 ? (
            <div className="space-y-4">
              {filteredEvents.map((event, index) => (
                <div key={index} className="flex items-center space-x-4 p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                  <div className="flex-shrink-0">
                    <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {event.event_type || 'Unknown Event'}
                      </span>
                      {event.severity && (
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          event.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200' :
                          event.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-200' :
                          event.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200' :
                          'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200'
                        }`}>
                          {event.severity}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      {event.description || 'No description available'}
                    </p>
                  </div>
                  
                  <div className="text-right">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {event.timeLabel}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {event.source || 'Unknown source'}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <ClockIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <p className="text-gray-500 dark:text-gray-400">
                No events found for the selected phase
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AttackTimeline;
