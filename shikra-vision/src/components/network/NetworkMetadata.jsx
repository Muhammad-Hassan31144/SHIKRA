import React from 'react';
import { 
  InformationCircleIcon,
  ClockIcon,
  DocumentTextIcon,
  ServerIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';

const NetworkMetadata = ({ metadata }) => {
  if (!metadata) return null;

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center mb-4">
        <InformationCircleIcon className="h-6 w-6 text-blue-500 mr-2" />
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Analysis Metadata</h3>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Analysis Info */}
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Analysis Information</h4>
          <div className="text-sm text-gray-900 dark:text-white">
            <div>Timestamp: {new Date(metadata.analysis_timestamp).toLocaleString()}</div>
            <div>Analyzer: v{metadata.analyzer_version}</div>
            {metadata.tshark_version && <div>TShark: v{metadata.tshark_version}</div>}
          </div>
        </div>

        {/* PCAP Info */}
        {metadata.pcap_info && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Capture Information</h4>
            <div className="text-sm text-gray-900 dark:text-white">
              <div>File: {metadata.pcap_info.filename}</div>
              <div>Size: {formatFileSize(metadata.pcap_info.file_size)}</div>
              <div>Duration: {metadata.pcap_info.duration}s</div>
              <div>Interface: {metadata.pcap_info.interface}</div>
            </div>
          </div>
        )}

        {/* Analysis Config */}
        {metadata.analysis_config && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Analysis Features</h4>
            <div className="text-sm text-gray-900 dark:text-white">
              {Object.entries(metadata.analysis_config).map(([key, value]) => (
                <div key={key} className="flex items-center">
                  <div className={`w-2 h-2 rounded-full mr-2 ${value ? 'bg-green-500' : 'bg-red-500'}`}></div>
                  {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}: {value ? 'Enabled' : 'Disabled'}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Statistics */}
        {metadata.statistics && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Traffic Statistics</h4>
            <div className="text-sm text-gray-900 dark:text-white">
              <div>Total Packets: {metadata.statistics.total_packets?.toLocaleString()}</div>
              <div>Total Bytes: {formatFileSize(metadata.statistics.total_bytes)}</div>
              <div>Unique Flows: {metadata.statistics.unique_flows?.toLocaleString()}</div>
            </div>
          </div>
        )}

        {/* Integrations */}
        {metadata.integrations && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Integrations</h4>
            <div className="text-sm text-gray-900 dark:text-white">
              {metadata.integrations.maxmind_geoip && (
                <div>GeoIP Lookups: {metadata.integrations.maxmind_geoip.lookups_performed}</div>
              )}
              {metadata.integrations.threat_intelligence && (
                <div>
                  <div>Threat Intel Sources: {metadata.integrations.threat_intelligence.sources?.join(', ')}</div>
                  <div>API Calls: {metadata.integrations.threat_intelligence.api_calls}</div>
                  <div>Hits: {metadata.integrations.threat_intelligence.hits}</div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkMetadata;
