import React, { useState } from 'react';
import {
  ShieldExclamationIcon,
  DocumentTextIcon,
  TagIcon,
  GlobeAltIcon,
  ChartBarIcon,
  BeakerIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  FunnelIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';

const MITRETechniques = ({ combinedData }) => {
  const [selectedTactic, setSelectedTactic] = useState('all');
  const [selectedSource, setSelectedSource] = useState('all');
  const [expandedTechnique, setExpandedTechnique] = useState(null);
  
  const summary = combinedData?.summary || {};
  const mitreTechniques = summary.mitre_techniques || [];

  // Group techniques by tactic
  const groupByTactic = () => {
    const grouped = mitreTechniques.reduce((acc, technique) => {
      const tactic = technique.tactic || 'Unknown';
      if (!acc[tactic]) {
        acc[tactic] = [];
      }
      acc[tactic].push(technique);
      return acc;
    }, {});
    
    return grouped;
  };

  const groupedTechniques = groupByTactic();

  // Filter techniques
  const getFilteredTechniques = () => {
    let filtered = mitreTechniques;
    
    if (selectedTactic !== 'all') {
      filtered = filtered.filter(technique => technique.tactic === selectedTactic);
    }
    
    if (selectedSource !== 'all') {
      filtered = filtered.filter(technique => 
        technique.sources && technique.sources.includes(selectedSource)
      );
    }
    
    return filtered;
  };

  const filteredTechniques = getFilteredTechniques();

  // Get statistics
  const getStats = () => {
    const tacticCounts = Object.keys(groupedTechniques).reduce((acc, tactic) => {
      acc[tactic] = groupedTechniques[tactic].length;
      return acc;
    }, {});

    const sourceCounts = mitreTechniques.reduce((acc, technique) => {
      if (technique.sources) {
        technique.sources.forEach(source => {
          acc[source] = (acc[source] || 0) + 1;
        });
      }
      return acc;
    }, {});

    const severityCounts = mitreTechniques.reduce((acc, technique) => {
      const severity = technique.severity || 'unknown';
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {});

    return { tacticCounts, sourceCounts, severityCounts };
  };

  const { tacticCounts, sourceCounts, severityCounts } = getStats();

  // MITRE ATT&CK tactic colors
  const getTacticColor = (tactic) => {
    const colors = {
      'initial-access': 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800',
      'execution': 'bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800',
      'persistence': 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800',
      'privilege-escalation': 'bg-pink-50 dark:bg-pink-900/20 text-pink-700 dark:text-pink-300 border-pink-200 dark:border-pink-800',
      'defense-evasion': 'bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800',
      'credential-access': 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-300 border-indigo-200 dark:border-indigo-800',
      'discovery': 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800',
      'lateral-movement': 'bg-cyan-50 dark:bg-cyan-900/20 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800',
      'collection': 'bg-teal-50 dark:bg-teal-900/20 text-teal-700 dark:text-teal-300 border-teal-200 dark:border-teal-800',
      'command-and-control': 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800',
      'exfiltration': 'bg-lime-50 dark:bg-lime-900/20 text-lime-700 dark:text-lime-300 border-lime-200 dark:border-lime-800',
      'impact': 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'
    };
    return colors[tactic.toLowerCase()] || 'bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-600';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-600 bg-red-50 dark:bg-red-900/20',
      high: 'text-orange-600 bg-orange-50 dark:bg-orange-900/20',
      medium: 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20',
      low: 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
      info: 'text-gray-600 bg-gray-50 dark:bg-gray-700'
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

  const formatTacticName = (tactic) => {
    return tactic.split('-').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  return (
    <div className="space-y-6">
      {/* MITRE Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ShieldExclamationIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Techniques</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {mitreTechniques.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <TagIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Unique Tactics</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {Object.keys(groupedTechniques).length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">High Severity</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(severityCounts.critical || 0) + (severityCounts.high || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <BeakerIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Data Sources</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {Object.keys(sourceCounts).length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tactic Overview */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">MITRE ATT&CK Tactics Overview</h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {Object.entries(tacticCounts).map(([tactic, count]) => (
            <div
              key={tactic}
              className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                selectedTactic === tactic 
                  ? getTacticColor(tactic)
                  : 'bg-gray-50 dark:bg-gray-700 border-gray-200 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-600'
              }`}
              onClick={() => setSelectedTactic(selectedTactic === tactic ? 'all' : tactic)}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">{formatTacticName(tactic)}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    {count} technique{count !== 1 ? 's' : ''}
                  </p>
                </div>
                <div className="text-lg font-bold">
                  {count}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Source and Severity Distribution */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Detection Sources</h3>
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
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Distribution</h3>
          <div className="space-y-3">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`w-3 h-3 rounded-full mr-2 ${getSeverityColor(severity)}`}></div>
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

      {/* Filter Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex flex-col space-y-4 lg:flex-row lg:items-center lg:justify-between lg:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <FunnelIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Tactic:</span>
            </div>
            <select
              value={selectedTactic}
              onChange={(e) => setSelectedTactic(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Tactics</option>
              {Object.keys(tacticCounts).map(tactic => (
                <option key={tactic} value={tactic}>{formatTacticName(tactic)}</option>
              ))}
            </select>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <BeakerIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Source:</span>
            </div>
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Sources</option>
              {Object.keys(sourceCounts).map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </select>
            
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredTechniques.length} techniques
            </span>
          </div>
        </div>
      </div>

      {/* Techniques List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Techniques</h3>
        </div>
        
        <div className="p-6">
          {filteredTechniques.length > 0 ? (
            <div className="space-y-4">
              {filteredTechniques.map((technique, index) => {
                const isExpanded = expandedTechnique === index;
                
                return (
                  <div
                    key={index}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden"
                  >
                    <div
                      className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700"
                      onClick={() => setExpandedTechnique(isExpanded ? null : index)}
                    >
                      <div className="flex items-center space-x-4 flex-1">
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-1 rounded text-xs font-medium border ${getTacticColor(technique.tactic || 'unknown')}`}>
                            {formatTacticName(technique.tactic || 'Unknown')}
                          </span>
                          {technique.severity && (
                            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(technique.severity)}`}>
                              {technique.severity}
                            </span>
                          )}
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2">
                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                              {technique.technique_id}
                            </span>
                            <span className="text-sm text-gray-600 dark:text-gray-400">
                              {technique.name}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500 dark:text-gray-400 truncate mt-1">
                            {technique.description}
                          </p>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          {technique.sources && technique.sources.map(source => (
                            <span
                              key={source}
                              className={`px-2 py-1 rounded text-xs font-medium ${getSourceColor(source)}`}
                            >
                              {source}
                            </span>
                          ))}
                        </div>
                      </div>
                      
                      <ChevronRightIcon 
                        className={`h-5 w-5 text-gray-400 ml-2 transition-transform ${
                          isExpanded ? 'transform rotate-90' : ''
                        }`}
                      />
                    </div>
                    
                    {isExpanded && (
                      <div className="border-t border-gray-200 dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-700">
                        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Technique Details</h4>
                            <div className="space-y-2 text-sm">
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Technique ID:</span>
                                <span className="text-gray-900 dark:text-white font-mono">{technique.technique_id}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-600 dark:text-gray-400">Tactic:</span>
                                <span className="text-gray-900 dark:text-white">{formatTacticName(technique.tactic || 'Unknown')}</span>
                              </div>
                              {technique.sub_technique && (
                                <div className="flex justify-between">
                                  <span className="text-gray-600 dark:text-gray-400">Sub-technique:</span>
                                  <span className="text-gray-900 dark:text-white">{technique.sub_technique}</span>
                                </div>
                              )}
                              {technique.confidence && (
                                <div className="flex justify-between">
                                  <span className="text-gray-600 dark:text-gray-400">Confidence:</span>
                                  <span className="text-gray-900 dark:text-white">{technique.confidence}%</span>
                                </div>
                              )}
                            </div>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Evidence</h4>
                            <div className="space-y-2">
                              {technique.evidence && technique.evidence.length > 0 ? (
                                technique.evidence.map((evidence, evidenceIndex) => (
                                  <div key={evidenceIndex} className="bg-white dark:bg-gray-800 p-3 rounded border">
                                    <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">Evidence #{evidenceIndex + 1}</p>
                                    <p className="text-sm text-gray-900 dark:text-white font-mono">{evidence}</p>
                                  </div>
                                ))
                              ) : (
                                <p className="text-sm text-gray-500 dark:text-gray-400">No evidence available</p>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        {technique.description && (
                          <div className="mt-4">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Description</h4>
                            <p className="text-sm text-gray-600 dark:text-gray-400">{technique.description}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12">
              <ShieldExclamationIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <p className="text-gray-500 dark:text-gray-400">
                No MITRE ATT&CK techniques found matching your criteria
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MITRETechniques;
