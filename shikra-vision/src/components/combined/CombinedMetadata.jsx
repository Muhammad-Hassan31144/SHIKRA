import React from 'react';
import {
  ClockIcon,
  DocumentTextIcon,
  ServerIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

const CombinedMetadata = ({ combinedData }) => {
  const meta = combinedData?.meta || {};
  const sources = meta.sources || {};
  const individualScores = meta.individual_risk_scores || {};
  const availableReports = meta.available_reports || [];

  const getRiskScoreColor = (score) => {
    if (score >= 8) return 'text-red-600 dark:text-red-400';
    if (score >= 6) return 'text-orange-600 dark:text-orange-400';
    if (score >= 4) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-green-600 dark:text-green-400';
  };

  const getRiskScoreBg = (score) => {
    if (score >= 8) return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
    if (score >= 6) return 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
    if (score >= 4) return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
    return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
  };

  const getSourceIcon = (source) => {
    switch (source) {
      case 'procmon':
        return <DocumentTextIcon className="h-5 w-5 text-blue-500" />;
      case 'memory':
        return <ServerIcon className="h-5 w-5 text-purple-500" />;
      case 'network':
        return <ChartBarIcon className="h-5 w-5 text-green-500" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Analysis Overview */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Analysis Overview</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Combined At</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {meta.combined_at ? new Date(meta.combined_at).toLocaleString() : 'Unknown'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Available Reports</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              {availableReports.length} of 3 sources
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Analysis Type</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">
              Multi-Source Correlation
            </dd>
          </div>
        </div>
      </div>

      {/* Data Sources Status */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ServerIcon className="h-6 w-6 text-green-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Data Sources</h3>
        </div>
        <div className="space-y-4">
          {['procmon', 'memory', 'network'].map(sourceType => {
            const isAvailable = availableReports.includes(sourceType);
            const sourcePath = sources[sourceType];
            const riskScore = individualScores[sourceType];
            
            return (
              <div key={sourceType} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center space-x-3">
                  {getSourceIcon(sourceType)}
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium text-gray-900 dark:text-white capitalize">
                        {sourceType} Analysis
                      </span>
                      {isAvailable ? (
                        <CheckCircleIcon className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircleIcon className="h-5 w-5 text-red-500" />
                      )}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                      {sourcePath || 'No data available'}
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  {riskScore !== undefined ? (
                    <div className={`px-3 py-1 rounded-full border ${getRiskScoreBg(riskScore)}`}>
                      <span className={`text-sm font-medium ${getRiskScoreColor(riskScore)}`}>
                        Risk: {riskScore.toFixed(1)}
                      </span>
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">No score</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Risk Score Comparison */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ExclamationTriangleIcon className="h-6 w-6 text-orange-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Individual Risk Scores</h3>
        </div>
        <div className="space-y-4">
          {Object.entries(individualScores).map(([source, score]) => (
            <div key={source} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                {getSourceIcon(source)}
                <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                  {source} Analysis
                </span>
              </div>
              <div className="flex items-center space-x-3">
                <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      score >= 8 ? 'bg-red-500' :
                      score >= 6 ? 'bg-orange-500' :
                      score >= 4 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${(score / 10) * 100}%` }}
                  ></div>
                </div>
                <span className={`text-sm font-medium ${getRiskScoreColor(score)}`}>
                  {score.toFixed(1)}/10
                </span>
              </div>
            </div>
          ))}
        </div>
        
        {Object.keys(individualScores).length > 0 && (
          <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
            <div className="flex items-center">
              <InformationCircleIcon className="h-5 w-5 text-blue-500 mr-2" />
              <div>
                <div className="text-sm font-medium text-blue-900 dark:text-blue-300">
                  Average Risk Score
                </div>
                <div className="text-sm text-blue-700 dark:text-blue-400">
                  {(Object.values(individualScores).reduce((sum, score) => sum + score, 0) / Object.values(individualScores).length).toFixed(2)}/10
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Statistics */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ChartBarIcon className="h-6 w-6 text-purple-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Analysis Statistics</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {availableReports.length}
            </div>
            <div className="text-sm text-blue-700 dark:text-blue-300">Data Sources</div>
          </div>
          
          <div className="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {availableReports.includes('procmon') ? '✓' : '✗'}
            </div>
            <div className="text-sm text-green-700 dark:text-green-300">Process Monitor</div>
          </div>
          
          <div className="text-center p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
            <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
              {availableReports.includes('memory') ? '✓' : '✗'}
            </div>
            <div className="text-sm text-purple-700 dark:text-purple-300">Memory Analysis</div>
          </div>
          
          <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {availableReports.includes('network') ? '✓' : '✗'}
            </div>
            <div className="text-sm text-orange-700 dark:text-orange-300">Network Analysis</div>
          </div>
        </div>
      </div>

      {/* Data Quality Assessment */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <CheckCircleIcon className="h-6 w-6 text-green-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Data Quality Assessment</h3>
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <span className="text-sm text-gray-700 dark:text-gray-300">Data Coverage</span>
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {Math.round((availableReports.length / 3) * 100)}% Complete
            </span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <span className="text-sm text-gray-700 dark:text-gray-300">Cross-Source Analysis</span>
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {availableReports.length >= 2 ? 'Enabled' : 'Limited'}
            </span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <span className="text-sm text-gray-700 dark:text-gray-300">Correlation Capability</span>
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {availableReports.length === 3 ? 'Full' : availableReports.length === 2 ? 'Partial' : 'Minimal'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CombinedMetadata;
