import React from 'react';
import useCyberStore from '../store/cyberStore';
import { GlobeAltIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';

const NetworkFlowChart = () => {
  const { threatData } = useCyberStore();
  const networkFlows = threatData.network?.network_flows || [];

  const getReputationColor = (reputation) => {
    switch (reputation) {
      case 'malicious':
        return 'text-red-600 bg-red-100';
      case 'suspicious':
        return 'text-orange-600 bg-orange-100';
      case 'clean':
        return 'text-green-600 bg-green-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (start, end) => {
    const duration = new Date(end) - new Date(start);
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  return (
    <div className="bg-white shadow rounded-lg">
      <div className="px-4 py-5 sm:p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg leading-6 font-medium text-gray-900">
            Network Flow Analysis
          </h3>
          <GlobeAltIcon className="h-5 w-5 text-gray-400" />
        </div>

        {/* Protocol Statistics */}
        {threatData.network?.metadata?.statistics && (
          <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="text-center p-3 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">
                {threatData.network.metadata.statistics.protocols.tcp?.toLocaleString()}
              </div>
              <div className="text-sm text-blue-600">TCP Packets</div>
            </div>
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">
                {threatData.network.metadata.statistics.protocols.udp?.toLocaleString()}
              </div>
              <div className="text-sm text-green-600">UDP Packets</div>
            </div>
            <div className="text-center p-3 bg-purple-50 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">
                {threatData.network.metadata.statistics.protocols.dns?.toLocaleString()}
              </div>
              <div className="text-sm text-purple-600">DNS Queries</div>
            </div>
            <div className="text-center p-3 bg-orange-50 rounded-lg">
              <div className="text-2xl font-bold text-orange-600">
                {threatData.network.metadata.statistics.unique_flows?.toLocaleString()}
              </div>
              <div className="text-sm text-orange-600">Unique Flows</div>
            </div>
          </div>
        )}

        {/* Network Flows Table */}
        <div className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Flow
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Protocol
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data Transfer
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Threat Intel
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {networkFlows.map((flow, index) => (
                  <tr key={flow.flow_id || index} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">
                        <div className="font-medium">
                          {flow.src_ip}:{flow.src_port}
                        </div>
                        <div className="text-gray-500">
                          → {flow.dst_ip}:{flow.dst_port}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {flow.protocol?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div>↑ {formatBytes(flow.bytes_sent || 0)}</div>
                      <div>↓ {formatBytes(flow.bytes_received || 0)}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {flow.start_time && flow.end_time ? 
                        formatDuration(flow.start_time, flow.end_time) : 
                        'Active'
                      }
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {flow.threat_intel && (
                        <div className="flex items-center space-x-2">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            getReputationColor(flow.threat_intel.dst_reputation)
                          }`}>
                            {flow.threat_intel.dst_reputation}
                          </span>
                          {flow.threat_intel.dst_reputation === 'malicious' && (
                            <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {networkFlows.length === 0 && (
          <div className="text-center py-8">
            <GlobeAltIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No network flows</h3>
            <p className="mt-1 text-sm text-gray-500">
              Network flow data will appear here when available.
            </p>
          </div>
        )}

        {/* Beaconing Analysis */}
        {threatData.network?.threat_hunting?.beaconing_analysis?.length > 0 && (
          <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600 mr-2" />
              <h4 className="text-sm font-medium text-yellow-800">
                Beaconing Activity Detected
              </h4>
            </div>
            <div className="mt-2 text-sm text-yellow-700">
              Potential C2 beaconing patterns found in network traffic. 
              Beacon score: {threatData.network.threat_hunting.beaconing_analysis[0].beacon_score}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkFlowChart;
