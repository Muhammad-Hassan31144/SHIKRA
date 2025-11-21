import React, { useState } from 'react';
import {
  DocumentTextIcon,
  PhotoIcon,
  FolderIcon,
  ServerIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  EyeIcon,
  ArrowDownTrayIcon,
  TagIcon,
  CalendarDaysIcon,
  UserIcon,
  ClockIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';

const EvidenceSummary = ({ combinedData }) => {
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSource, setSelectedSource] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedEvidence, setExpandedEvidence] = useState(null);
  
  const analysis = combinedData?.analysis || {};
  const evidenceSummary = analysis.evidence_summary || {};
  
  const artifacts = evidenceSummary.artifacts || [];
  const evidenceChain = evidenceSummary.evidence_chain || [];
  const forensicNotes = evidenceSummary.forensic_notes || [];
  const recommendations = evidenceSummary.recommendations || [];

  // Filter artifacts based on category, source, and search term
  const getFilteredArtifacts = () => {
    let filtered = artifacts;
    
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(artifact => artifact.type === selectedCategory);
    }
    
    if (selectedSource !== 'all') {
      filtered = filtered.filter(artifact => artifact.source === selectedSource);
    }
    
    if (searchTerm) {
      filtered = filtered.filter(artifact => 
        artifact.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        artifact.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        artifact.path?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }
    
    return filtered;
  };

  const filteredArtifacts = getFilteredArtifacts();

  // Get statistics
  const getStats = () => {
    const typeCounts = artifacts.reduce((acc, artifact) => {
      acc[artifact.type] = (acc[artifact.type] || 0) + 1;
      return acc;
    }, {});

    const sourceCounts = artifacts.reduce((acc, artifact) => {
      acc[artifact.source] = (acc[artifact.source] || 0) + 1;
      return acc;
    }, {});

    const severityCounts = artifacts.reduce((acc, artifact) => {
      const severity = artifact.severity || 'unknown';
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {});

    return { typeCounts, sourceCounts, severityCounts };
  };

  const { typeCounts, sourceCounts, severityCounts } = getStats();

  // Get unique values for filters
  const uniqueTypes = [...new Set(artifacts.map(a => a.type))].filter(Boolean);
  const uniqueSources = [...new Set(artifacts.map(a => a.source))].filter(Boolean);

  const getTypeIcon = (type) => {
    const icons = {
      file: DocumentTextIcon,
      image: PhotoIcon,
      directory: FolderIcon,
      registry: ServerIcon,
      network: ShieldCheckIcon,
      memory: PhotoIcon,
      process: ServerIcon,
      log: DocumentTextIcon
    };
    return icons[type.toLowerCase()] || DocumentTextIcon;
  };

  const getTypeColor = (type) => {
    const colors = {
      file: 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800',
      image: 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800',
      directory: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800',
      registry: 'bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800',
      network: 'bg-cyan-50 dark:bg-cyan-900/20 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800',
      memory: 'bg-pink-50 dark:bg-pink-900/20 text-pink-700 dark:text-pink-300 border-pink-200 dark:border-pink-800',
      process: 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-300 border-indigo-200 dark:border-indigo-800',
      log: 'bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800'
    };
    return colors[type.toLowerCase()] || 'bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-600';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200',
      high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200',
      low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200',
      info: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
    };
    return colors[severity] || colors.info;
  };

  const getSourceColor = (source) => {
    const colors = {
      procmon: 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300',
      volatility: 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300',
      pcap: 'bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300'
    };
    return colors[source] || 'bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300';
  };

  const formatFileSize = (size) => {
    if (!size) return 'Unknown';
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
    return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

  const formatPath = (path) => {
    if (!path) return 'Unknown';
    if (path.length > 60) {
      return '...' + path.substring(path.length - 57);
    }
    return path;
  };

  return (
    <div className="space-y-6">
      {/* Evidence Summary Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Artifacts</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {artifacts.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Evidence Chain</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {evidenceChain.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">High Priority</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(severityCounts.critical || 0) + (severityCounts.high || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <UserIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Forensic Notes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {forensicNotes.length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Type Distribution */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Artifact Types</h3>
          <div className="space-y-3">
            {Object.entries(typeCounts).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`px-2 py-1 rounded text-xs font-medium ${getTypeColor(type)}`}>
                    {type}
                  </div>
                </div>
                <span className="text-sm font-bold text-gray-900 dark:text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Data Sources</h3>
          <div className="space-y-3">
            {Object.entries(sourceCounts).map(([source, count]) => (
              <div key={source} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`px-2 py-1 rounded text-xs font-medium ${getSourceColor(source)}`}>
                    {source}
                  </div>
                </div>
                <span className="text-sm font-bold text-gray-900 dark:text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Levels</h3>
          <div className="space-y-3">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`w-3 h-3 rounded-full mr-2 ${getSeverityColor(severity).split(' ')[0]}`}></div>
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize">
                    {severity}
                  </span>
                </div>
                <span className="text-sm font-bold text-gray-900 dark:text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Search and Filter Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="flex items-center space-x-2">
            <TagIcon className="h-5 w-5 text-gray-500" />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Types</option>
              {uniqueTypes.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </div>
          
          <div className="flex items-center space-x-2">
            <ServerIcon className="h-5 w-5 text-gray-500" />
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Sources</option>
              {uniqueSources.map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </select>
          </div>
          
          <div className="relative">
            <MagnifyingGlassIcon className="h-5 w-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search artifacts..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>
        </div>
        
        <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
          Showing {filteredArtifacts.length} of {artifacts.length} artifacts
        </div>
      </div>

      {/* Artifacts List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Digital Evidence Artifacts</h3>
        </div>
        
        <div className="p-6">
          {filteredArtifacts.length > 0 ? (
            <div className="space-y-4">
              {filteredArtifacts.map((artifact, index) => {
                const TypeIcon = getTypeIcon(artifact.type);
                const isExpanded = expandedEvidence === index;
                
                return (
                  <div
                    key={index}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden"
                  >
                    <div
                      className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700"
                      onClick={() => setExpandedEvidence(isExpanded ? null : index)}
                    >
                      <div className="flex items-center space-x-4 flex-1">
                        <TypeIcon className="h-6 w-6 text-gray-500" />
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2">
                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                              {artifact.name || 'Unknown Artifact'}
                            </span>
                            <span className={`px-2 py-1 rounded text-xs font-medium border ${getTypeColor(artifact.type)}`}>
                              {artifact.type}
                            </span>
                            {artifact.severity && (
                              <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(artifact.severity)}`}>
                                {artifact.severity}
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 truncate mt-1">
                            {formatPath(artifact.path)}
                          </p>
                        </div>
                        
                        <div className="flex items-center space-x-4">
                          <div className="text-right">
                            <p className="text-sm text-gray-900 dark:text-white">
                              {formatFileSize(artifact.size)}
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              {artifact.source}
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      <div className="ml-2">
                        <EyeIcon className="h-5 w-5 text-gray-400" />
                      </div>
                    </div>
                    
                    {isExpanded && (
                      <div className="border-t border-gray-200 dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-700">
                        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Artifact Details</h4>
                            <div className="space-y-2 text-sm">
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Full Path:</span>
                                <span className="text-gray-900 dark:text-white font-mono text-xs break-all">
                                  {artifact.path || 'Unknown'}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Size:</span>
                                <span className="text-gray-900 dark:text-white">{formatFileSize(artifact.size)}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Source:</span>
                                <span className="text-gray-900 dark:text-white">{artifact.source}</span>
                              </div>
                              {artifact.hash && (
                                <div className="flex justify-between">
                                  <span className="text-gray-600 dark:text-gray-400">Hash:</span>
                                  <span className="text-gray-900 dark:text-white font-mono text-xs">
                                    {artifact.hash.substring(0, 16)}...
                                  </span>
                                </div>
                              )}
                              {artifact.created_time && (
                                <div className="flex justify-between">
                                  <span className="text-gray-600 dark:text-gray-400">Created:</span>
                                  <span className="text-gray-900 dark:text-white">
                                    {new Date(artifact.created_time).toLocaleString()}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Analysis</h4>
                            <div className="space-y-2">
                              {artifact.description && (
                                <div>
                                  <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">Description:</p>
                                  <p className="text-sm text-gray-900 dark:text-white">{artifact.description}</p>
                                </div>
                              )}
                              {artifact.analysis_notes && (
                                <div>
                                  <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">Analysis Notes:</p>
                                  <div className="bg-white dark:bg-gray-800 p-2 rounded border text-xs text-gray-600 dark:text-gray-400">
                                    {artifact.analysis_notes}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12">
              <DocumentTextIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <p className="text-gray-500 dark:text-gray-400">
                No artifacts found matching your criteria
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Evidence Chain */}
      {evidenceChain.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Evidence Chain of Custody</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {evidenceChain.map((chainItem, index) => (
                <div key={index} className="flex items-center space-x-4 p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
                  <div className="flex-shrink-0 w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-medium">
                    {index + 1}
                  </div>
                  
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {chainItem.action || 'Unknown Action'}
                      </span>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        by {chainItem.analyst || 'Unknown'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      {chainItem.description || 'No description available'}
                    </p>
                  </div>
                  
                  <div className="text-right">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {chainItem.timestamp ? new Date(chainItem.timestamp).toLocaleString() : 'Unknown'}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Forensic Notes */}
      {forensicNotes.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Forensic Analysis Notes</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {forensicNotes.map((note, index) => (
                <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {note.title || `Note ${index + 1}`}
                    </span>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {note.analyst || 'Unknown Analyst'}
                      </span>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {note.timestamp ? new Date(note.timestamp).toLocaleString() : 'Unknown'}
                      </span>
                    </div>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {note.content || 'No content available'}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Investigation Recommendations</h3>
          </div>
          <div className="p-6">
            <div className="space-y-3">
              {recommendations.map((recommendation, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <CheckCircleIcon className="h-5 w-5 text-blue-600 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-blue-900 dark:text-blue-200">
                      {recommendation.title || `Recommendation ${index + 1}`}
                    </p>
                    <p className="text-sm text-blue-700 dark:text-blue-300 mt-1">
                      {recommendation.description || 'No description available'}
                    </p>
                    {recommendation.priority && (
                      <span className={`inline-block mt-2 px-2 py-1 rounded text-xs font-medium ${
                        recommendation.priority === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200' :
                        recommendation.priority === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200' :
                        'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200'
                      }`}>
                        {recommendation.priority} priority
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EvidenceSummary;
