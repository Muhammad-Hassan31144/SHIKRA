import React, { useState } from 'react';
import {
  ExclamationTriangleIcon,
  GlobeAltIcon,
  HashtagIcon,
  FolderIcon,
  ServerIcon,
  DocumentTextIcon,
  KeyIcon,
  LockClosedIcon,
  EyeIcon,
  MagnifyingGlassIcon,
  FunnelIcon
} from '@heroicons/react/24/outline';

const IOCAnalysis = ({ combinedData }) => {
  const [selectedIOCType, setSelectedIOCType] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  
  const summary = combinedData?.summary || {};
  const iocs = summary.iocs || {};

  // All IOC types with their data and metadata
  const iocTypes = [
    { key: 'ips', label: 'IP Addresses', icon: GlobeAltIcon, color: 'blue', data: iocs.ips || [] },
    { key: 'domains', label: 'Domains', icon: GlobeAltIcon, color: 'green', data: iocs.domains || [] },
    { key: 'urls', label: 'URLs', icon: GlobeAltIcon, color: 'purple', data: iocs.urls || [] },
    { key: 'hashes_sha256', label: 'SHA256 Hashes', icon: HashtagIcon, color: 'red', data: iocs.hashes_sha256 || [] },
    { key: 'hashes_md5', label: 'MD5 Hashes', icon: HashtagIcon, color: 'orange', data: iocs.hashes_md5 || [] },
    { key: 'paths', label: 'File Paths', icon: FolderIcon, color: 'yellow', data: iocs.paths || [] },
    { key: 'registry_keys', label: 'Registry Keys', icon: KeyIcon, color: 'indigo', data: iocs.registry_keys || [] },
    { key: 'mutexes', label: 'Mutexes', icon: LockClosedIcon, color: 'pink', data: iocs.mutexes || [] },
    { key: 'file_names', label: 'File Names', icon: DocumentTextIcon, color: 'gray', data: iocs.file_names || [] },
    { key: 'process_names', label: 'Process Names', icon: ServerIcon, color: 'cyan', data: iocs.process_names || [] }
  ];

  // Filter IOCs based on selected type and search term
  const getFilteredIOCs = () => {
    let filtered = iocTypes;
    
    if (selectedIOCType !== 'all') {
      filtered = filtered.filter(type => type.key === selectedIOCType);
    }
    
    if (searchTerm) {
      filtered = filtered.map(type => ({
        ...type,
        data: type.data.filter(ioc => 
          ioc.toLowerCase().includes(searchTerm.toLowerCase())
        )
      })).filter(type => type.data.length > 0);
    }
    
    return filtered;
  };

  const filteredIOCs = getFilteredIOCs();
  const totalIOCs = iocTypes.reduce((sum, type) => sum + type.data.length, 0);

  const getColorClasses = (color) => {
    const colorMap = {
      blue: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800 text-blue-900 dark:text-blue-100',
      green: 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-900 dark:text-green-100',
      purple: 'bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800 text-purple-900 dark:text-purple-100',
      red: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-900 dark:text-red-100',
      orange: 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800 text-orange-900 dark:text-orange-100',
      yellow: 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800 text-yellow-900 dark:text-yellow-100',
      indigo: 'bg-indigo-50 dark:bg-indigo-900/20 border-indigo-200 dark:border-indigo-800 text-indigo-900 dark:text-indigo-100',
      pink: 'bg-pink-50 dark:bg-pink-900/20 border-pink-200 dark:border-pink-800 text-pink-900 dark:text-pink-100',
      gray: 'bg-gray-50 dark:bg-gray-700 border-gray-200 dark:border-gray-600 text-gray-900 dark:text-gray-100',
      cyan: 'bg-cyan-50 dark:bg-cyan-900/20 border-cyan-200 dark:border-cyan-800 text-cyan-900 dark:text-cyan-100'
    };
    return colorMap[color] || colorMap.gray;
  };

  const getIconColor = (color) => {
    const colorMap = {
      blue: 'text-blue-500',
      green: 'text-green-500',
      purple: 'text-purple-500',
      red: 'text-red-500',
      orange: 'text-orange-500',
      yellow: 'text-yellow-500',
      indigo: 'text-indigo-500',
      pink: 'text-pink-500',
      gray: 'text-gray-500',
      cyan: 'text-cyan-500'
    };
    return colorMap[color] || colorMap.gray;
  };

  const formatIOC = (ioc, type) => {
    // Truncate long IOCs for display
    if (type === 'urls' && ioc.length > 50) {
      return ioc.substring(0, 50) + '...';
    }
    if (type === 'paths' && ioc.length > 60) {
      return '...' + ioc.substring(ioc.length - 57);
    }
    if (type === 'registry_keys' && ioc.length > 60) {
      return '...' + ioc.substring(ioc.length - 57);
    }
    return ioc;
  };

  return (
    <div className="space-y-6">
      {/* IOC Summary Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total IOCs</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {totalIOCs}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <GlobeAltIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Network IOCs</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(iocs.ips?.length || 0) + (iocs.domains?.length || 0) + (iocs.urls?.length || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <HashtagIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">File Hashes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(iocs.hashes_sha256?.length || 0) + (iocs.hashes_md5?.length || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <FolderIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">File Artifacts</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(iocs.paths?.length || 0) + (iocs.file_names?.length || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ServerIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">System Artifacts</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(iocs.registry_keys?.length || 0) + (iocs.mutexes?.length || 0) + (iocs.process_names?.length || 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* IOC Type Overview Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {iocTypes.map(type => {
          const Icon = type.icon;
          return (
            <div
              key={type.key}
              className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                selectedIOCType === type.key 
                  ? getColorClasses(type.color)
                  : 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
              onClick={() => setSelectedIOCType(selectedIOCType === type.key ? 'all' : type.key)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <Icon className={`h-5 w-5 ${getIconColor(type.color)}`} />
                  <div className="ml-2">
                    <p className="text-xs text-gray-600 dark:text-gray-400">{type.label}</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white">
                      {type.data.length}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Search and Filter Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex flex-col space-y-4 lg:flex-row lg:items-center lg:justify-between lg:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <FunnelIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filter:</span>
            </div>
            <select
              value={selectedIOCType}
              onChange={(e) => setSelectedIOCType(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All IOC Types</option>
              {iocTypes.map(type => (
                <option key={type.key} value={type.key}>{type.label}</option>
              ))}
            </select>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="relative">
              <MagnifyingGlassIcon className="h-5 w-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search IOCs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredIOCs.reduce((sum, type) => sum + type.data.length, 0)} IOCs
            </span>
          </div>
        </div>
      </div>

      {/* IOC Details */}
      <div className="space-y-6">
        {filteredIOCs.map(type => {
          const Icon = type.icon;
          
          if (type.data.length === 0) return null;
          
          return (
            <div key={type.key} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <Icon className={`h-6 w-6 ${getIconColor(type.color)} mr-2`} />
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{type.label}</h3>
                  </div>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {type.data.length} items
                  </span>
                </div>
              </div>
              
              <div className="p-6">
                <div className="grid grid-cols-1 gap-3">
                  {type.data.map((ioc, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors"
                    >
                      <div className="flex items-center space-x-3 flex-1 min-w-0">
                        <Icon className={`h-4 w-4 ${getIconColor(type.color)} flex-shrink-0`} />
                        <span 
                          className="font-mono text-sm text-gray-900 dark:text-white truncate"
                          title={ioc}
                        >
                          {formatIOC(ioc, type.key)}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => navigator.clipboard.writeText(ioc)}
                          className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                          title="Copy to clipboard"
                        >
                          <DocumentTextIcon className="h-4 w-4" />
                        </button>
                        <button
                          className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                          title="View details"
                        >
                          <EyeIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {filteredIOCs.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
          <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
          <p className="text-gray-500 dark:text-gray-400">
            No IOCs found matching your search criteria
          </p>
        </div>
      )}
    </div>
  );
};

export default IOCAnalysis;
