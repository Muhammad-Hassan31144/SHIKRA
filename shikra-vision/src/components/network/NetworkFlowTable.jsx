import React, { useState } from 'react';
import { 
  GlobeAltIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  MapPinIcon,
  MagnifyingGlassIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon
} from '@heroicons/react/24/outline';

const ITEMS_PER_PAGE = 15;

const NetworkFlowTable = ({ networkFlows }) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterReputation, setFilterReputation] = useState('all');
  const [sortBy, setSortBy] = useState('start_time');
  const [sortOrder, setSortOrder] = useState('desc');

  if (!networkFlows || networkFlows.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="text-center py-12">
          <GlobeAltIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No network flows</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Network flow data will appear here when available.
          </p>
        </div>
      </div>
    );
  }

  // Filter and sort flows
  const filteredFlows = networkFlows.filter(flow => {
    const matchesSearch = flow.dst_ip?.includes(searchTerm) ||
                         flow.src_ip?.includes(searchTerm) ||
                         flow.application_layer?.tls_info?.server_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         flow.threat_intel?.dst_categories?.some(cat => 
                           cat.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesReputation = filterReputation === 'all' || flow.threat_intel?.dst_reputation === filterReputation;
    
    return matchesSearch && matchesReputation;
  });

  // Sort flows
  filteredFlows.sort((a, b) => {
    let aVal = a[sortBy];
    let bVal = b[sortBy];
    
    if (sortBy === 'start_time' || sortBy === 'end_time') {
      aVal = new Date(aVal).getTime();
      bVal = new Date(bVal).getTime();
    }
    
    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = bVal.toLowerCase();
    }
    
    if (sortOrder === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });

  // Pagination
  const totalPages = Math.ceil(filteredFlows.length / ITEMS_PER_PAGE);
  const paginatedFlows = filteredFlows.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  const formatBytes = (bytes) => {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getReputationColor = (reputation) => {
    switch (reputation) {
      case 'malicious':
        return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200';
      case 'suspicious':
        return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200';
      case 'clean':
        return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200';
      default:
        return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200';
    }
  };

  const getFlowIcon = (flow) => {
    if (flow.threat_intel?.dst_reputation === 'malicious') {
      return <ExclamationTriangleIcon className="h-6 w-6 text-red-600 dark:text-red-400" />;
    } else if (flow.threat_intel?.dst_reputation === 'suspicious') {
      return <ShieldExclamationIcon className="h-6 w-6 text-orange-600 dark:text-orange-400" />;
    } else {
      return <GlobeAltIcon className="h-6 w-6 text-green-600 dark:text-green-400" />;
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
      <div className="px-4 py-5 sm:p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
            Network Flow Analysis
          </h3>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Showing {paginatedFlows.length} of {filteredFlows.length} flows
          </div>
        </div>

        {/* Search and Filter Section */}
        <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div className="col-span-2">
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search IPs, domains, categories..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                />
              </div>
            </div>
            
            {/* Reputation Filter */}
            <div>
              <select
                value={filterReputation}
                onChange={(e) => setFilterReputation(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              >
                <option value="all">All Reputation</option>
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
                <option value="clean">Clean</option>
              </select>
            </div>
            
            {/* Sort */}
            <div>
              <select
                value={`${sortBy}-${sortOrder}`}
                onChange={(e) => {
                  const [field, order] = e.target.value.split('-');
                  setSortBy(field);
                  setSortOrder(order);
                }}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              >
                <option value="start_time-desc">Latest First</option>
                <option value="start_time-asc">Oldest First</option>
                <option value="bytes_sent-desc">Largest Outbound</option>
                <option value="bytes_received-desc">Largest Inbound</option>
                <option value="duration-desc">Longest Duration</option>
              </select>
            </div>
          </div>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Flow Details
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Protocol/Ports
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Traffic Volume
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Duration
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Reputation
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Geography
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Application Layer
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {paginatedFlows.map((flow, index) => (
                <tr key={`flow-${flow.flow_id}-${index}`} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="flex-shrink-0 h-10 w-10">
                        <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                          flow.threat_intel?.dst_reputation === 'malicious' ? 'bg-red-100 dark:bg-red-900' :
                          flow.threat_intel?.dst_reputation === 'suspicious' ? 'bg-orange-100 dark:bg-orange-900' :
                          'bg-green-100 dark:bg-green-900'
                        }`}>
                          {getFlowIcon(flow)}
                        </div>
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                          {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {flow.application_layer?.tls_info?.server_name || flow.flow_id}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900 dark:text-white">{flow.protocol?.toUpperCase()}</div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {flow.application_layer?.detected_protocol && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                          {flow.application_layer.detected_protocol.toUpperCase()}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900 dark:text-white">
                      Total: {formatBytes((flow.bytes_sent || 0) + (flow.bytes_received || 0))}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center space-x-2">
                      <span className="flex items-center">
                        <ArrowTrendingUpIcon className="h-3 w-3 mr-1 text-red-500" />
                        {formatBytes(flow.bytes_sent || 0)}
                      </span>
                      <span className="flex items-center">
                        <ArrowTrendingDownIcon className="h-3 w-3 mr-1 text-green-500" />
                        {formatBytes(flow.bytes_received || 0)}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center text-sm text-gray-900 dark:text-white">
                      <ClockIcon className="h-4 w-4 mr-1 text-gray-400" />
                      {(flow.duration || 0).toFixed(1)}s
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400">
                      {flow.packets_sent || 0} / {flow.packets_received || 0} packets
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      getReputationColor(flow.threat_intel?.dst_reputation)
                    }`}>
                      {flow.threat_intel?.dst_reputation || 'unknown'}
                    </span>
                    {flow.threat_intel?.confidence && (
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {(flow.threat_intel.confidence * 100).toFixed(0)}% confidence
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    <div className="flex items-center">
                      <MapPinIcon className="h-4 w-4 text-gray-400 mr-1" />
                      <div>
                        <div>{flow.geoip?.dst_geo?.country || 'Unknown'}</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          {flow.geoip?.dst_geo?.city || 'Unknown'}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="space-y-1">
                      {flow.application_layer?.tls_info && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200">
                          TLS {flow.application_layer.tls_info.version}
                        </span>
                      )}
                      {flow.threat_intel?.dst_categories?.slice(0, 2).map((category, idx) => (
                        <span key={idx} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200 mr-1">
                          {category}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6">
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Page {currentPage} of {totalPages}
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
                className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm disabled:opacity-50 bg-white dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                <ChevronLeftIcon className="h-4 w-4" />
              </button>
              <button
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
                className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm disabled:opacity-50 bg-white dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                <ChevronRightIcon className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkFlowTable;
