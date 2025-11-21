import React, { useState } from 'react';
import {
  LinkIcon,
  MagnifyingGlassIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  DocumentTextIcon,
  HashtagIcon,
  GlobeAltIcon,
  CpuChipIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const CorrelationAnalysis = ({ combinedData }) => {
  const [selectedCorrelationType, setSelectedCorrelationType] = useState('all');
  const [showDetails, setShowDetails] = useState({});

  const summary = combinedData?.summary || {};
  const analysis = combinedData?.analysis || {};
  const correlations = summary.correlations || [];
  const crossCorrelations = analysis.cross_correlations || {};

  // Filter correlations based on selected type
  const filteredCorrelations = selectedCorrelationType === 'all' ? 
    correlations : 
    correlations.filter(corr => corr.type === selectedCorrelationType);

  // Prepare data for correlation type chart
  const correlationTypeData = Object.entries(crossCorrelations.correlation_types || {}).map(([type, count]) => ({
    name: type.replace(/ Correlation/g, ''),
    value: count,
    fullName: type
  }));

  // Color scheme for charts
  const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#F97316'];

  const getCorrelationIcon = (type) => {
    switch (type) {
      case 'Process Correlation':
        return <CpuChipIcon className="h-5 w-5 text-blue-500" />;
      case 'File Hash Correlation':
        return <DocumentTextIcon className="h-5 w-5 text-green-500" />;
      case 'Network IOC Correlation':
        return <GlobeAltIcon className="h-5 w-5 text-orange-500" />;
      case 'MITRE Technique Correlation':
        return <ShieldCheckIcon className="h-5 w-5 text-red-500" />;
      default:
        return <LinkIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getConfidenceColor = (confidence) => {
    switch (confidence) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300';
      case 'low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const toggleDetails = (index) => {
    setShowDetails(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const getCorrelationStrengthColor = (strength) => {
    switch (strength) {
      case 'high':
        return 'text-green-600 dark:text-green-400';
      case 'medium':
        return 'text-yellow-600 dark:text-yellow-400';
      case 'low':
        return 'text-red-600 dark:text-red-400';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Correlation Summary Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <LinkIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Correlations</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {crossCorrelations.total_correlations || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">High Confidence</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {crossCorrelations.high_confidence_correlations?.length || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Correlation Strength</p>
              <p className={`text-lg font-bold capitalize ${getCorrelationStrengthColor(crossCorrelations.correlation_strength)}`}>
                {crossCorrelations.correlation_strength || 'Unknown'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <HashtagIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Correlation Types</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {Object.keys(crossCorrelations.correlation_types || {}).length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Correlation Type Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <LinkIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Correlation Type Distribution</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={correlationTypeData}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {correlationTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Correlation Breakdown */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <MagnifyingGlassIcon className="h-6 w-6 text-green-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Correlation Breakdown</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={correlationTypeData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="name" 
                angle={-45}
                textAnchor="end"
                height={80}
              />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#3B82F6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Correlation Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Correlation Analysis</h3>
          <select
            value={selectedCorrelationType}
            onChange={(e) => setSelectedCorrelationType(e.target.value)}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
          >
            <option value="all">All Correlation Types</option>
            <option value="Process Correlation">Process Correlations</option>
            <option value="File Hash Correlation">File Hash Correlations</option>
            <option value="Network IOC Correlation">Network IOC Correlations</option>
            <option value="MITRE Technique Correlation">MITRE Technique Correlations</option>
          </select>
        </div>

        <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
          Showing {filteredCorrelations.length} of {correlations.length} correlations
        </div>
      </div>

      {/* Detailed Correlations */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Correlation Details</h3>
        </div>
        
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {filteredCorrelations.length > 0 ? (
            filteredCorrelations.map((correlation, index) => (
              <div key={index} className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className="flex-shrink-0">
                      {getCorrelationIcon(correlation.type)}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-2">
                        <h4 className="text-lg font-medium text-gray-900 dark:text-white">
                          {correlation.type}
                        </h4>
                        {correlation.confidence && (
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${getConfidenceColor(correlation.confidence)}`}>
                            {correlation.confidence.toUpperCase()}
                          </span>
                        )}
                        {correlation.evidence_count && (
                          <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300">
                            {correlation.evidence_count} evidence
                          </span>
                        )}
                      </div>
                      
                      <p className="text-gray-600 dark:text-gray-400 mb-3">
                        {correlation.description || 'No description available'}
                      </p>
                      
                      {/* Key Information */}
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 mb-3">
                        {correlation.name && (
                          <div>
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Name:</span>
                            <span className="ml-2 text-sm text-gray-900 dark:text-white font-mono">
                              {correlation.name}
                            </span>
                          </div>
                        )}
                        
                        {correlation.pid && (
                          <div>
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400">PID:</span>
                            <span className="ml-2 text-sm text-gray-900 dark:text-white font-mono">
                              {correlation.pid}
                            </span>
                          </div>
                        )}
                        
                        {correlation.technique_id && (
                          <div>
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400">MITRE ID:</span>
                            <span className="ml-2 text-sm text-gray-900 dark:text-white font-mono">
                              {correlation.technique_id}
                            </span>
                          </div>
                        )}
                        
                        {correlation.hash && (
                          <div className="sm:col-span-2 lg:col-span-3">
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Hash:</span>
                            <span className="ml-2 text-sm text-gray-900 dark:text-white font-mono break-all">
                              {correlation.hash}
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Sources */}
                      {correlation.sources && correlation.sources.length > 0 && (
                        <div className="mb-3">
                          <span className="text-xs font-medium text-gray-500 dark:text-gray-400 mr-2">Sources:</span>
                          {correlation.sources.map((source, srcIndex) => (
                            <span key={srcIndex} className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 mr-2 mb-1">
                              {source}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Artifact Indicators */}
                      <div className="flex items-center space-x-4 mb-3">
                        {correlation.has_memory_artifacts !== undefined && (
                          <div className="flex items-center space-x-1">
                            {correlation.has_memory_artifacts ? 
                              <CheckCircleIcon className="h-4 w-4 text-green-500" /> : 
                              <XCircleIcon className="h-4 w-4 text-red-500" />
                            }
                            <span className="text-xs text-gray-600 dark:text-gray-400">Memory Artifacts</span>
                          </div>
                        )}
                        
                        {correlation.has_network_artifacts !== undefined && (
                          <div className="flex items-center space-x-1">
                            {correlation.has_network_artifacts ? 
                              <CheckCircleIcon className="h-4 w-4 text-green-500" /> : 
                              <XCircleIcon className="h-4 w-4 text-red-500" />
                            }
                            <span className="text-xs text-gray-600 dark:text-gray-400">Network Artifacts</span>
                          </div>
                        )}
                      </div>

                      {/* Network Indicators */}
                      {correlation.network_indicators && (
                        <div className="mb-3">
                          <h5 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Network Indicators</h5>
                          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                            {correlation.network_indicators.suspicious_ips && correlation.network_indicators.suspicious_ips.length > 0 && (
                              <div>
                                <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Suspicious IPs:</span>
                                <div className="mt-1">
                                  {correlation.network_indicators.suspicious_ips.map((ip, ipIndex) => (
                                    <span key={ipIndex} className="inline-block px-2 py-1 text-xs font-mono bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-300 rounded mr-1 mb-1">
                                      {ip}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                            
                            {correlation.network_indicators.suspicious_domains && correlation.network_indicators.suspicious_domains.length > 0 && (
                              <div>
                                <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Suspicious Domains:</span>
                                <div className="mt-1">
                                  {correlation.network_indicators.suspicious_domains.map((domain, domainIndex) => (
                                    <span key={domainIndex} className="inline-block px-2 py-1 text-xs font-mono bg-orange-100 dark:bg-orange-900/20 text-orange-800 dark:text-orange-300 rounded mr-1 mb-1">
                                      {domain}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Details toggle */}
                      {correlation.details && correlation.details.length > 0 && showDetails[index] && (
                        <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                          <h5 className="font-medium text-gray-900 dark:text-white mb-2">Detailed Evidence</h5>
                          <ul className="space-y-1 text-sm">
                            {correlation.details.map((detail, detailIndex) => (
                              <li key={detailIndex} className="text-gray-600 dark:text-gray-400">
                                • {detail}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {correlation.details && correlation.details.length > 0 && (
                    <button
                      onClick={() => toggleDetails(index)}
                      className="ml-4 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                      title={showDetails[index] ? 'Hide details' : 'Show details'}
                    >
                      <MagnifyingGlassIcon className="h-5 w-5" />
                    </button>
                  )}
                </div>
              </div>
            ))
          ) : (
            <div className="p-6 text-center text-gray-500 dark:text-gray-400">
              <LinkIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <p>No correlations found for the selected type</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CorrelationAnalysis;
