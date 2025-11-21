import React from 'react';
import useCyberStore from '../store/cyberStore';
import { formatTimestamp } from '../utils/sampleData';
import { 
  ClockIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

const ThreatTimeline = () => {
  const { threatData } = useCyberStore();

  // Combine timeline events from all data sources
  const timelineEvents = React.useMemo(() => {
    const events = [];
    
    // Add memory analysis timeline
    if (threatData.memory?.threat_assessment?.timeline) {
      threatData.memory.threat_assessment.timeline.forEach(event => {
        events.push({
          ...event,
          source: 'Memory Analysis',
          type: 'memory'
        });
      });
    }
    
    // Add network analysis timeline
    if (threatData.network?.timeline) {
      threatData.network.timeline.forEach(event => {
        events.push({
          ...event,
          source: 'Network Analysis',
          type: 'network'
        });
      });
    }
    
    // Add procmon alerts as timeline events
    if (threatData.procmon?.alerts) {
      threatData.procmon.alerts.forEach(alert => {
        events.push({
          timestamp: alert.timestamp,
          event: alert.title,
          severity: alert.severity,
          source: 'Process Monitor',
          type: 'procmon',
          description: alert.description
        });
      });
    }
    
    return events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }, [threatData]);

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />;
      case 'high':
        return <ShieldExclamationIcon className="h-5 w-5 text-orange-600" />;
      case 'medium':
        return <InformationCircleIcon className="h-5 w-5 text-yellow-600" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-blue-600" />;
    }
  };

  const getSeverityBadge = (severity) => {
    const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
    switch (severity) {
      case 'critical':
        return `${baseClasses} bg-red-100 text-red-800`;
      case 'high':
        return `${baseClasses} bg-orange-100 text-orange-800`;
      case 'medium':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      default:
        return `${baseClasses} bg-blue-100 text-blue-800`;
    }
  };

  const getSourceBadge = (type) => {
    const baseClasses = "inline-flex items-center px-2 py-1 rounded text-xs font-medium";
    switch (type) {
      case 'memory':
        return `${baseClasses} bg-purple-100 text-purple-800`;
      case 'network':
        return `${baseClasses} bg-green-100 text-green-800`;
      case 'procmon':
        return `${baseClasses} bg-blue-100 text-blue-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  return (
    <div className="bg-white shadow rounded-lg">
      <div className="px-4 py-5 sm:p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg leading-6 font-medium text-gray-900">
            Threat Timeline
          </h3>
          <ClockIcon className="h-5 w-5 text-gray-400" />
        </div>
        
        <div className="flow-root">
          <ul role="list" className="-mb-8">
            {timelineEvents.map((event, eventIdx) => (
              <li key={`${event.timestamp}-${eventIdx}`}>
                <div className="relative pb-8">
                  {eventIdx !== timelineEvents.length - 1 ? (
                    <span
                      className="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200"
                      aria-hidden="true"
                    />
                  ) : null}
                  <div className="relative flex space-x-3">
                    <div>
                      <span className="h-8 w-8 rounded-full bg-gray-100 flex items-center justify-center ring-8 ring-white">
                        {getSeverityIcon(event.severity)}
                      </span>
                    </div>
                    <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                      <div>
                        <p className="text-sm text-gray-900 font-medium">
                          {event.event}
                        </p>
                        {event.description && (
                          <p className="text-sm text-gray-500 mt-1">
                            {event.description}
                          </p>
                        )}
                        <div className="mt-2 flex space-x-2">
                          <span className={getSeverityBadge(event.severity)}>
                            {event.severity}
                          </span>
                          <span className={getSourceBadge(event.type)}>
                            {event.source}
                          </span>
                        </div>
                      </div>
                      <div className="text-right text-sm whitespace-nowrap text-gray-500">
                        <time dateTime={event.timestamp}>
                          {formatTimestamp(event.timestamp)}
                        </time>
                      </div>
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
        
        {timelineEvents.length === 0 && (
          <div className="text-center py-8">
            <ClockIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No timeline events</h3>
            <p className="mt-1 text-sm text-gray-500">
              Timeline events will appear here as threats are detected.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatTimeline;
