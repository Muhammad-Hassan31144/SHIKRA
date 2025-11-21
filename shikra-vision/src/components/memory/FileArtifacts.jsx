import React from 'react';
import {
  DocumentIcon,
  FolderIcon,
  CalendarIcon,
  HashtagIcon,
  ShieldCheckIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

const FileArtifacts = ({ memoryData }) => {
  const fileArtifacts = memoryData?.analysis_results?.file_artifacts || [];

  const getStatusBadge = (status) => {
    const badges = {
      'allocated': { color: 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200', label: 'Allocated' },
      'deleted': { color: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200', label: 'Deleted' },
      'unallocated': { color: 'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200', label: 'Unallocated' }
    };
    return badges[status] || badges.allocated;
  };

  const getVirusTotalBadge = (verdict) => {
    const badges = {
      'malicious': { color: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200', label: 'Malicious' },
      'suspicious': { color: 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200', label: 'Suspicious' },
      'clean': { color: 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200', label: 'Clean' },
      'unknown': { color: 'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200', label: 'Unknown' }
    };
    return badges[verdict] || badges.unknown;
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (fileArtifacts.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8">
        <div className="text-center">
          <DocumentIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No File Artifacts</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            No file artifacts were detected in the memory analysis.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <DocumentIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Files</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{fileArtifacts.length}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Resident Files</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {fileArtifacts.filter(f => f.resident).length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <FolderIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Deleted Files</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {fileArtifacts.filter(f => f.allocation_status === 'deleted').length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <HashtagIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Size</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatFileSize(fileArtifacts.reduce((acc, f) => acc + (f.size || 0), 0))}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* File Artifacts */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <DocumentIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">File Artifacts</h3>
        </div>
        
        <div className="space-y-4">
          {fileArtifacts.map((file, index) => {
            const statusBadge = getStatusBadge(file.allocation_status);
            const vtBadge = file.virustotal ? getVirusTotalBadge(file.virustotal.verdict) : null;
            
            return (
              <div key={index} className={`border rounded-lg p-4 ${
                file.virustotal?.verdict === 'malicious' 
                  ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' 
                  : file.allocation_status === 'deleted'
                  ? 'border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-900/20'
                  : 'border-gray-200 dark:border-gray-600'
              }`}>
                <div className="flex justify-between items-start mb-3">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <h4 className="font-medium text-gray-900 dark:text-white">
                        {file.filename}
                      </h4>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusBadge.color}`}>
                        {statusBadge.label}
                      </span>
                      {file.resident && (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                          Resident
                        </span>
                      )}
                      {vtBadge && (
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${vtBadge.color}`}>
                          VT: {vtBadge.label}
                        </span>
                      )}
                    </div>
                    
                    <div className="space-y-2">
                      {/* File Path */}
                      <div className="flex items-start space-x-2">
                        <FolderIcon className="h-4 w-4 text-gray-400 mt-0.5 flex-shrink-0" />
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Full Path:</p>
                          <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                            {file.full_path}
                          </p>
                        </div>
                      </div>

                      {/* File Details */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div className="flex items-center space-x-2">
                          <HashtagIcon className="h-4 w-4 text-gray-400" />
                          <div>
                            <span className="text-gray-500 dark:text-gray-400">Size:</span>
                            <span className="ml-1 text-gray-900 dark:text-white">
                              {formatFileSize(file.size || 0)}
                            </span>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <CalendarIcon className="h-4 w-4 text-gray-400" />
                          <div>
                            <span className="text-gray-500 dark:text-gray-400">Created:</span>
                            <span className="ml-1 text-gray-900 dark:text-white">
                              {file.created ? new Date(file.created).toLocaleDateString() : 'N/A'}
                            </span>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <ClockIcon className="h-4 w-4 text-gray-400" />
                          <div>
                            <span className="text-gray-500 dark:text-gray-400">Modified:</span>
                            <span className="ml-1 text-gray-900 dark:text-white">
                              {file.modified ? new Date(file.modified).toLocaleDateString() : 'N/A'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Hash Information */}
                      {file.hash && (
                        <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                          <h5 className="font-medium text-gray-900 dark:text-white mb-2">File Hashes</h5>
                          <div className="space-y-1 text-sm font-mono">
                            {file.hash.md5 && (
                              <div>
                                <span className="text-gray-500 dark:text-gray-400">MD5:</span>
                                <span className="ml-2 text-gray-900 dark:text-white break-all">{file.hash.md5}</span>
                              </div>
                            )}
                            {file.hash.sha256 && (
                              <div>
                                <span className="text-gray-500 dark:text-gray-400">SHA256:</span>
                                <span className="ml-2 text-gray-900 dark:text-white break-all">{file.hash.sha256}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* VirusTotal Results */}
                      {file.virustotal && (
                        <div className={`mt-3 p-3 rounded-lg ${
                          file.virustotal.verdict === 'malicious' 
                            ? 'bg-red-100 dark:bg-red-900/30' 
                            : file.virustotal.verdict === 'suspicious'
                            ? 'bg-orange-100 dark:bg-orange-900/30'
                            : 'bg-green-100 dark:bg-green-900/30'
                        }`}>
                          <div className="flex items-start space-x-2">
                            <ShieldCheckIcon className={`h-5 w-5 mt-0.5 ${
                              file.virustotal.verdict === 'malicious' 
                                ? 'text-red-600 dark:text-red-400' 
                                : file.virustotal.verdict === 'suspicious'
                                ? 'text-orange-600 dark:text-orange-400'
                                : 'text-green-600 dark:text-green-400'
                            }`} />
                            <div className="flex-1">
                              <h5 className={`font-medium ${
                                file.virustotal.verdict === 'malicious' 
                                  ? 'text-red-800 dark:text-red-200' 
                                  : file.virustotal.verdict === 'suspicious'
                                  ? 'text-orange-800 dark:text-orange-200'
                                  : 'text-green-800 dark:text-green-200'
                              }`}>
                                VirusTotal Analysis
                              </h5>
                              <div className="text-sm mt-1 space-y-1">
                                <div>
                                  <span className="text-gray-500 dark:text-gray-400">Detection Ratio:</span>
                                  <span className="ml-1 font-medium">{file.virustotal.detection_ratio}</span>
                                </div>
                                <div>
                                  <span className="text-gray-500 dark:text-gray-400">Scan Date:</span>
                                  <span className="ml-1">{new Date(file.virustotal.scan_date).toLocaleDateString()}</span>
                                </div>
                                <div>
                                  <span className="text-gray-500 dark:text-gray-400">Verdict:</span>
                                  <span className="ml-1 font-medium capitalize">{file.virustotal.verdict}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default FileArtifacts;
