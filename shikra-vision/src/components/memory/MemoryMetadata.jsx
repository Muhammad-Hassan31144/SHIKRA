import React from 'react';
import {
  ComputerDesktopIcon,
  CpuChipIcon,
  ServerIcon,
  ClockIcon,
  DocumentTextIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

const MemoryMetadata = ({ memoryData }) => {
  const metadata = memoryData?.metadata || {};
  const systemInfo = metadata.system_info || {};
  const memoryImage = metadata.memory_image || {};
  const integrations = metadata.integrations || {};
  const pluginsExecuted = metadata.plugins_executed || [];

  return (
    <div className="space-y-6">
      {/* System Information */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ComputerDesktopIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">System Information</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Hostname</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {systemInfo.hostname || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Operating System</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {systemInfo.os || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Architecture</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {systemInfo.architecture || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Kernel Version</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {systemInfo.kernel_version || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Build</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {systemInfo.build || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Timezone</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {systemInfo.timezone || 'Unknown'}
            </dd>
          </div>
        </div>
      </div>

      {/* Memory Image Information */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ServerIcon className="h-6 w-6 text-green-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Memory Image</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Filename</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {memoryImage.filename || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Size</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {memoryImage.size ? `${(memoryImage.size / (1024 * 1024 * 1024)).toFixed(2)} GB` : 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Acquisition Time</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {memoryImage.acquisition_time ? new Date(memoryImage.acquisition_time).toLocaleString() : 'Unknown'}
            </dd>
          </div>
          {memoryImage.hash && (
            <>
              <div className="col-span-full">
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">MD5 Hash</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono break-all">
                  {memoryImage.hash.md5 || 'N/A'}
                </dd>
              </div>
              <div className="col-span-full">
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">SHA256 Hash</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono break-all">
                  {memoryImage.hash.sha256 || 'N/A'}
                </dd>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Analysis Information */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ClockIcon className="h-6 w-6 text-purple-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Analysis Details</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Analysis Timestamp</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {metadata.analysis_timestamp ? new Date(metadata.analysis_timestamp).toLocaleString() : 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Volatility Version</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {metadata.volatility_version || 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Analyzer Version</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
              {metadata.analyzer_version || 'Unknown'}
            </dd>
          </div>
        </div>
      </div>

      {/* Plugins Executed */}
      {pluginsExecuted.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <CpuChipIcon className="h-6 w-6 text-orange-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Plugins Executed</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Plugin
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Execution Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Records Found
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {pluginsExecuted.map((plugin, index) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white font-mono">
                      {plugin.plugin}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {plugin.execution_time}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        plugin.status === 'success' 
                          ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                          : 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                      }`}>
                        {plugin.status === 'success' ? (
                          <CheckCircleIcon className="h-3 w-3 mr-1" />
                        ) : (
                          <XCircleIcon className="h-3 w-3 mr-1" />
                        )}
                        {plugin.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {plugin.records_found || 0}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Integrations */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <DocumentTextIcon className="h-6 w-6 text-indigo-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">External Integrations</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {integrations.virustotal && (
            <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">VirusTotal</h4>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Status:</span>
                  <span className={`${integrations.virustotal.enabled ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                    {integrations.virustotal.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">API Calls:</span>
                  <span className="text-gray-900 dark:text-white">{integrations.virustotal.api_calls || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Rate Limit Remaining:</span>
                  <span className="text-gray-900 dark:text-white">{integrations.virustotal.rate_limit_remaining || 0}</span>
                </div>
              </div>
            </div>
          )}
          {integrations.maxmind_geoip && (
            <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">MaxMind GeoIP</h4>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Status:</span>
                  <span className={`${integrations.maxmind_geoip.enabled ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                    {integrations.maxmind_geoip.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Database Version:</span>
                  <span className="text-gray-900 dark:text-white">{integrations.maxmind_geoip.database_version || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Lookups Performed:</span>
                  <span className="text-gray-900 dark:text-white">{integrations.maxmind_geoip.lookups_performed || 0}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MemoryMetadata;
