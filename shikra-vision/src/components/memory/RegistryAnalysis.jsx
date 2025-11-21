import React from 'react';
import {
  DocumentTextIcon,
  KeyIcon,
  FolderIcon,
  CalendarIcon,
  HashtagIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';

const RegistryAnalysis = ({ memoryData }) => {
  const registryAnalysis = memoryData?.analysis_results?.registry_analysis || [];

  const getPersistenceBadge = (technique) => {
    const badges = {
      'registry_autorun': { color: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200', label: 'Autorun' },
      'service_creation': { color: 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200', label: 'Service' },
      'startup_folder': { color: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200', label: 'Startup' },
      'scheduled_task': { color: 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200', label: 'Task' },
      'dll_hijacking': { color: 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200', label: 'DLL Hijack' },
      'default': { color: 'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200', label: 'Unknown' }
    };
    return badges[technique] || badges.default;
  };

  const getValueTypeDisplay = (type) => {
    const types = {
      'REG_SZ': 'String',
      'REG_DWORD': 'DWORD',
      'REG_BINARY': 'Binary',
      'REG_MULTI_SZ': 'Multi-String',
      'REG_EXPAND_SZ': 'Expandable String',
      'REG_QWORD': 'QWORD'
    };
    return types[type] || type;
  };

  if (registryAnalysis.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8">
        <div className="text-center">
          <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No Registry Analysis</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            No registry artifacts were detected in the memory analysis.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Registry Entries</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{registryAnalysis.length}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <KeyIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Persistence Keys</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {registryAnalysis.filter(entry => entry.persistence_technique).length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <FolderIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Unique Hives</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {new Set(registryAnalysis.map(entry => entry.hive.split('\\')[0])).size}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Registry Entries */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <DocumentTextIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Registry Analysis</h3>
        </div>
        
        <div className="space-y-4">
          {registryAnalysis.map((entry, index) => {
            const persistenceBadge = getPersistenceBadge(entry.persistence_technique);
            
            return (
              <div key={index} className={`border rounded-lg p-4 ${
                entry.persistence_technique 
                  ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' 
                  : 'border-gray-200 dark:border-gray-600'
              }`}>
                <div className="flex justify-between items-start mb-3">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <h4 className="font-medium text-gray-900 dark:text-white">
                        {entry.value_name}
                      </h4>
                      {entry.persistence_technique && (
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${persistenceBadge.color}`}>
                          <ShieldCheckIcon className="h-3 w-3 mr-1" />
                          {persistenceBadge.label}
                        </span>
                      )}
                    </div>
                    
                    <div className="space-y-2">
                      {/* Registry Path */}
                      <div className="flex items-start space-x-2">
                        <FolderIcon className="h-4 w-4 text-gray-400 mt-0.5 flex-shrink-0" />
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Registry Path:</p>
                          <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                            {entry.hive}\\{entry.key}
                          </p>
                        </div>
                      </div>

                      {/* Value Data */}
                      <div className="flex items-start space-x-2">
                        <HashtagIcon className="h-4 w-4 text-gray-400 mt-0.5 flex-shrink-0" />
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Value Data:</p>
                          <p className="text-sm font-mono text-gray-900 dark:text-white break-all bg-gray-100 dark:bg-gray-700 p-2 rounded">
                            {entry.value_data}
                          </p>
                        </div>
                      </div>

                      {/* Metadata */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div className="flex items-center space-x-2">
                          <DocumentTextIcon className="h-4 w-4 text-gray-400" />
                          <div>
                            <span className="text-gray-500 dark:text-gray-400">Type:</span>
                            <span className="ml-1 text-gray-900 dark:text-white">
                              {getValueTypeDisplay(entry.value_type)}
                            </span>
                          </div>
                        </div>
                        
                        {entry.last_write_time && (
                          <div className="flex items-center space-x-2">
                            <CalendarIcon className="h-4 w-4 text-gray-400" />
                            <div>
                              <span className="text-gray-500 dark:text-gray-400">Last Write:</span>
                              <span className="ml-1 text-gray-900 dark:text-white">
                                {new Date(entry.last_write_time).toLocaleString()}
                              </span>
                            </div>
                          </div>
                        )}
                        
                        {entry.persistence_technique && (
                          <div className="flex items-center space-x-2">
                            <KeyIcon className="h-4 w-4 text-gray-400" />
                            <div>
                              <span className="text-gray-500 dark:text-gray-400">Technique:</span>
                              <span className="ml-1 text-gray-900 dark:text-white">
                                {entry.persistence_technique.replace('_', ' ')}
                              </span>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Threat Assessment */}
                {entry.persistence_technique && (
                  <div className="mt-3 p-3 bg-red-100 dark:bg-red-900/30 rounded-lg">
                    <div className="flex items-start space-x-2">
                      <ShieldCheckIcon className="h-5 w-5 text-red-600 dark:text-red-400 mt-0.5" />
                      <div>
                        <h5 className="font-medium text-red-800 dark:text-red-200">Persistence Mechanism Detected</h5>
                        <p className="text-sm text-red-700 dark:text-red-300 mt-1">
                          This registry entry enables automatic execution of software and may be used for persistence by malware.
                          {entry.persistence_technique === 'registry_autorun' && ' The Run key is commonly abused for malware persistence.'}
                          {entry.persistence_technique === 'service_creation' && ' Service entries can provide system-level persistence.'}
                          {entry.persistence_technique === 'startup_folder' && ' Startup folder entries execute during user login.'}
                          {entry.persistence_technique === 'scheduled_task' && ' Scheduled tasks can execute at specified intervals.'}
                          {entry.persistence_technique === 'dll_hijacking' && ' DLL hijacking can redirect legitimate processes to malicious code.'}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default RegistryAnalysis;
