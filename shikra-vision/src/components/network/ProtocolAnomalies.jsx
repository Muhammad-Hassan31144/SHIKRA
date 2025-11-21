import React from 'react';
import { 
  ExclamationTriangleIcon,
  BugAntIcon,
  EyeIcon,
  FlagIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

const ProtocolAnomalies = ({ protocolAnomalies }) => {
  if (!protocolAnomalies || protocolAnomalies.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="text-center py-8">
          <BugAntIcon className="mx-auto h-8 w-8 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No protocol anomalies detected</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Protocol anomaly data will appear here when detected.
          </p>
        </div>
      </div>
    );
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 border-red-200 dark:border-red-800';
      case 'high':
        return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200 border-orange-200 dark:border-orange-800';
      case 'medium':
        return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 border-yellow-200 dark:border-yellow-800';
      case 'low':
        return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 border-blue-200 dark:border-blue-800';
      default:
        return 'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200 border-gray-200 dark:border-gray-800';
    }
  };

  const getAnomalyIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'port_scan':
        return <EyeIcon className="h-5 w-5" />;
      case 'dns_tunneling':
        return <BugAntIcon className="h-5 w-5" />;
      default:
        return <ExclamationTriangleIcon className="h-5 w-5" />;
    }
  };

  const getAnomalyDescription = (anomaly) => {
    switch (anomaly.type?.toLowerCase()) {
      case 'port_scan':
        return `Port scan detected from ${anomaly.src_ip} targeting ${anomaly.target_range}. ${anomaly.ports_scanned?.length || 0} ports scanned over ${anomaly.scan_duration}s.`;
      case 'dns_tunneling':
        return `DNS tunneling detected from ${anomaly.src_ip}. ${anomaly.query_frequency} queries with avg size ${anomaly.average_query_size} bytes.`;
      default:
        return `Anomaly detected: ${anomaly.type}`;
    }
  };

  // Sort by severity and timestamp
  const sortedAnomalies = [...protocolAnomalies].sort((a, b) => {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const aSeverity = severityOrder[a.severity?.toLowerCase()] || 0;
    const bSeverity = severityOrder[b.severity?.toLowerCase()] || 0;
    
    if (aSeverity !== bSeverity) {
      return bSeverity - aSeverity; // Higher severity first
    }
    
    return new Date(b.timestamp) - new Date(a.timestamp); // More recent first
  });

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center mb-6">
        <BugAntIcon className="h-6 w-6 text-orange-500 mr-2" />
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Protocol Anomalies</h3>
        <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200">
          {protocolAnomalies.length} detected
        </span>
      </div>

      <div className="space-y-4">
        {sortedAnomalies.map((anomaly, index) => (
          <div 
            key={`anomaly-${anomaly.anomaly_id || index}`}
            className={`p-4 rounded-lg border-l-4 ${getSeverityColor(anomaly.severity)}`}
          >
            <div className="flex items-start">
              <div className="flex-shrink-0">
                <div className={`p-2 rounded-full ${getSeverityColor(anomaly.severity)}`}>
                  {getAnomalyIcon(anomaly.type)}
                </div>
              </div>
              
              <div className="ml-4 flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="text-lg font-medium text-gray-900 dark:text-white">
                    {anomaly.type?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown Anomaly'}
                  </h4>
                  <div className="flex items-center space-x-2">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(anomaly.severity)}`}>
                      {anomaly.severity?.toUpperCase() || 'UNKNOWN'}
                    </span>
                    {anomaly.detection_confidence && (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                        {(anomaly.detection_confidence * 100).toFixed(0)}% confidence
                      </span>
                    )}
                  </div>
                </div>
                
                <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
                  {getAnomalyDescription(anomaly)}
                </p>
                
                <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <div className="flex items-center text-gray-500 dark:text-gray-400">
                      <ClockIcon className="h-4 w-4 mr-1" />
                      Timestamp
                    </div>
                    <div className="text-gray-900 dark:text-white">
                      {new Date(anomaly.timestamp).toLocaleString()}
                    </div>
                  </div>
                  
                  {anomaly.src_ip && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Source IP</div>
                      <div className="text-gray-900 dark:text-white font-mono">{anomaly.src_ip}</div>
                    </div>
                  )}
                  
                  {anomaly.target_range && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Target Range</div>
                      <div className="text-gray-900 dark:text-white font-mono">{anomaly.target_range}</div>
                    </div>
                  )}
                  
                  {anomaly.dst_ip && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Destination IP</div>
                      <div className="text-gray-900 dark:text-white font-mono">{anomaly.dst_ip}</div>
                    </div>
                  )}
                  
                  {anomaly.ports_scanned && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Ports Scanned</div>
                      <div className="text-gray-900 dark:text-white">
                        {anomaly.ports_scanned.length} ports
                        <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          {anomaly.ports_scanned.slice(0, 10).join(', ')}
                          {anomaly.ports_scanned.length > 10 && '...'}
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {anomaly.suspicious_domains && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Suspicious Domains</div>
                      <div className="text-gray-900 dark:text-white">
                        {anomaly.suspicious_domains.length} domains
                        <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          {anomaly.suspicious_domains.slice(0, 2).join(', ')}
                          {anomaly.suspicious_domains.length > 2 && '...'}
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {anomaly.scan_duration && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Duration</div>
                      <div className="text-gray-900 dark:text-white">{anomaly.scan_duration}s</div>
                    </div>
                  )}
                  
                  {anomaly.query_frequency && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Query Frequency</div>
                      <div className="text-gray-900 dark:text-white">{anomaly.query_frequency} queries</div>
                    </div>
                  )}
                  
                  {anomaly.packets_count && (
                    <div>
                      <div className="text-gray-500 dark:text-gray-400">Packets</div>
                      <div className="text-gray-900 dark:text-white">{anomaly.packets_count}</div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ProtocolAnomalies;
