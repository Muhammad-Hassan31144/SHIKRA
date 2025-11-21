import React from 'react';
import {
  ComputerDesktopIcon,
  ClockIcon,
  DocumentTextIcon,
  CpuChipIcon,
  FolderIcon,
  GlobeAltIcon,
  Cog6ToothIcon
} from '@heroicons/react/24/outline';

const ProcmonMetadata = ({ procmonData }) => {
  const metadata = procmonData?.metadata || {};
  const hostInfo = metadata.host_info || {};
  const configApplied = metadata.config_applied || {};
  const eventTypes = metadata.event_types || {};

  return (
    <div className="space-y-6">
      {/* Collection Information */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Collection Information</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Collection Start</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {metadata.collection_start ? new Date(metadata.collection_start).toLocaleString() : 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Collection End</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {metadata.collection_end ? new Date(metadata.collection_end).toLocaleString() : 'Ongoing'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Duration</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {metadata.collection_start && metadata.collection_end ? 
                `${Math.round((new Date(metadata.collection_end) - new Date(metadata.collection_start)) / (1000 * 60))} minutes` :
                'Ongoing'
              }
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Parser Version</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {metadata.parser_version || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Events</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {metadata.total_events?.toLocaleString() || '0'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Aggregation Window</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {configApplied.aggregation_window || 'N/A'}
            </dd>
          </div>
        </div>
      </div>

      {/* Host Information */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ComputerDesktopIcon className="h-6 w-6 text-green-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Host Information</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Hostname</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {hostInfo.hostname || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Operating System</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {hostInfo.os_version || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Architecture</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {hostInfo.architecture || 'Unknown'}
            </dd>
          </div>
        </div>
      </div>

      {/* Event Type Distribution */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <DocumentTextIcon className="h-6 w-6 text-purple-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Type Distribution</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
            <div className="flex items-center">
              <CpuChipIcon className="h-8 w-8 text-blue-500" />
              <div className="ml-3">
                <p className="text-sm text-blue-700 dark:text-blue-300">Process Events</p>
                <p className="text-2xl font-bold text-blue-900 dark:text-blue-100">
                  {eventTypes.process?.toLocaleString() || '0'}
                </p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
            <div className="flex items-center">
              <FolderIcon className="h-8 w-8 text-green-500" />
              <div className="ml-3">
                <p className="text-sm text-green-700 dark:text-green-300">File Events</p>
                <p className="text-2xl font-bold text-green-900 dark:text-green-100">
                  {eventTypes.file?.toLocaleString() || '0'}
                </p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-800">
            <div className="flex items-center">
              <DocumentTextIcon className="h-8 w-8 text-orange-500" />
              <div className="ml-3">
                <p className="text-sm text-orange-700 dark:text-orange-300">Registry Events</p>
                <p className="text-2xl font-bold text-orange-900 dark:text-orange-100">
                  {eventTypes.registry?.toLocaleString() || '0'}
                </p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg border border-indigo-200 dark:border-indigo-800">
            <div className="flex items-center">
              <GlobeAltIcon className="h-8 w-8 text-indigo-500" />
              <div className="ml-3">
                <p className="text-sm text-indigo-700 dark:text-indigo-300">Network Events</p>
                <p className="text-2xl font-bold text-indigo-900 dark:text-indigo-100">
                  {eventTypes.network?.toLocaleString() || '0'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Applied */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <Cog6ToothIcon className="h-6 w-6 text-orange-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Configuration Settings</h3>
        </div>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Filters */}
          <div>
            <h4 className="font-medium text-gray-900 dark:text-white mb-2">Applied Filters</h4>
            <div className="space-y-2">
              {configApplied.filters && configApplied.filters.length > 0 ? 
                configApplied.filters.map((filter, index) => (
                  <span key={index} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 mr-2 mb-2">
                    {filter.replace(/_/g, ' ')}
                  </span>
                )) :
                <span className="text-sm text-gray-500 dark:text-gray-400">No filters applied</span>
              }
            </div>
          </div>

          {/* Enrichment */}
          <div>
            <h4 className="font-medium text-gray-900 dark:text-white mb-2">Enrichment Options</h4>
            <div className="space-y-2">
              {configApplied.enrichment && configApplied.enrichment.length > 0 ? 
                configApplied.enrichment.map((enrichment, index) => (
                  <span key={index} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 mr-2 mb-2">
                    {enrichment.replace(/_/g, ' ')}
                  </span>
                )) :
                <span className="text-sm text-gray-500 dark:text-gray-400">No enrichment applied</span>
              }
            </div>
          </div>

          {/* Summary Stats */}
          <div>
            <h4 className="font-medium text-gray-900 dark:text-white mb-2">Collection Summary</h4>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Total Events:</span>
                <span className="text-gray-900 dark:text-white font-medium">
                  {metadata.total_events?.toLocaleString() || '0'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Event Types:</span>
                <span className="text-gray-900 dark:text-white font-medium">
                  {Object.keys(eventTypes).length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Filters:</span>
                <span className="text-gray-900 dark:text-white font-medium">
                  {configApplied.filters?.length || 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Enrichments:</span>
                <span className="text-gray-900 dark:text-white font-medium">
                  {configApplied.enrichment?.length || 0}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProcmonMetadata;
