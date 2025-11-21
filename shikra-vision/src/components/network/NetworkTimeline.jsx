import React from 'react';
import { 
  ClockIcon,
  FlagIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

const NetworkTimeline = ({ timeline, iocs }) => {
  if (!timeline && !iocs) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="text-center py-8">
          <ClockIcon className="mx-auto h-8 w-8 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No timeline data</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Network timeline will appear here when available.
          </p>
        </div>
      </div>
    );
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'border-red-500 bg-red-50 dark:bg-red-900/20';
      case 'high':
        return 'border-orange-500 bg-orange-50 dark:bg-orange-900/20';
      case 'medium':
        return 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20';
      case 'low':
        return 'border-blue-500 bg-blue-50 dark:bg-blue-900/20';
      default:
        return 'border-gray-500 bg-gray-50 dark:bg-gray-900/20';
    }
  };

  const getSeverityIcon = (severity) => {
    const iconClass = "h-4 w-4";
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <div className={`${iconClass} bg-red-500 rounded-full`}></div>;
      case 'high':
        return <div className={`${iconClass} bg-orange-500 rounded-full`}></div>;
      case 'medium':
        return <div className={`${iconClass} bg-yellow-500 rounded-full`}></div>;
      case 'low':
        return <div className={`${iconClass} bg-blue-500 rounded-full`}></div>;
      default:
        return <div className={`${iconClass} bg-gray-500 rounded-full`}></div>;
    }
  };

  const getIOCIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'ip':
        return '🌐';
      case 'domain':
        return '🔗';
      case 'hash':
        return '🔐';
      case 'ja3':
        return '🔍';
      default:
        return '📌';
    }
  };

  // Sort timeline events by timestamp
  const sortedTimeline = timeline ? [...timeline].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)) : [];

  return (
    <div className="space-y-6">
      {/* Timeline */}
      {timeline && timeline.length > 0 && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center mb-6">
            <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Network Activity Timeline</h3>
          </div>

          <div className="relative">
            <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-gray-600"></div>
            
            <div className="space-y-6">
              {sortedTimeline.map((event, index) => (
                <div key={index} className="relative flex items-start">
                  <div className="absolute left-2 w-4 h-4 -translate-x-1/2">
                    {getSeverityIcon(event.severity)}
                  </div>
                  
                  <div className={`ml-8 p-4 rounded-lg border-l-4 ${getSeverityColor(event.severity)} flex-1`}>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                        {event.event}
                      </h4>
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                          event.severity === 'critical' ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200' :
                          event.severity === 'high' ? 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200' :
                          event.severity === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200' :
                          event.severity === 'low' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                          'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200'
                        }`}>
                          {event.severity?.toUpperCase()}
                        </span>
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                          {event.category?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                      <ClockIcon className="h-4 w-4 mr-1" />
                      {new Date(event.timestamp).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* IOCs (Indicators of Compromise) */}
      {iocs && iocs.length > 0 && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center mb-6">
            <FlagIcon className="h-6 w-6 text-red-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Indicators of Compromise (IOCs)</h3>
            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
              {iocs.length} indicators
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {iocs.map((ioc, index) => (
              <div key={index} className="p-4 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center mb-2">
                      <span className="text-lg mr-2">{getIOCIcon(ioc.type)}</span>
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                        {ioc.type?.toUpperCase()}
                      </span>
                      <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                        {ioc.confidence}% confidence
                      </span>
                    </div>
                    
                    <div className="mb-2">
                      <div className="text-sm font-medium text-gray-900 dark:text-white break-all">
                        {ioc.value}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {ioc.context}
                      </div>
                    </div>
                    
                    <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
                      <ClockIcon className="h-3 w-3 mr-1" />
                      First seen: {new Date(ioc.first_seen).toLocaleString()}
                    </div>
                  </div>
                  
                  <div className="ml-4">
                    <button 
                      className="inline-flex items-center px-2 py-1 border border-gray-300 dark:border-gray-600 rounded text-xs font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                      onClick={() => navigator.clipboard?.writeText(ioc.value)}
                    >
                      Copy
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary */}
      {(timeline || iocs) && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center mb-4">
            <InformationCircleIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Activity Summary</h3>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {timeline && (
              <>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">
                    {timeline.filter(e => e.severity === 'critical').length}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Critical Events</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">
                    {timeline.filter(e => e.severity === 'high').length}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">High Severity</div>
                </div>
              </>
            )}
            
            {iocs && (
              <>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    {iocs.filter(i => i.confidence >= 90).length}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">High Confidence IOCs</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {new Set(iocs.map(i => i.type)).size}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">IOC Types</div>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkTimeline;
