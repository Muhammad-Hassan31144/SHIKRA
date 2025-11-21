import React, { useMemo } from 'react';
import useCyberStore from '../store/cyberStore';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  ChartBarIcon,
  DocumentTextIcon,
  ClockIcon,
  LinkIcon
} from '@heroicons/react/24/outline';

const CombinedReport = () => {
  const { threatData } = useCyberStore();
  
  // Combine data from all sources with memoization
  const combinedData = useMemo(() => ({
    memory: threatData?.memory || null,
    network: threatData?.network || null,
    procmon: threatData?.procmon || null
  }), [threatData]);

  const getRiskLevel = (score) => {
    if (score >= 8) return { level: 'Critical', color: 'text-red-600 dark:text-red-400', bg: 'bg-red-100 dark:bg-red-900' };
    if (score >= 6) return { level: 'High', color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-100 dark:bg-orange-900' };
    if (score >= 4) return { level: 'Medium', color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-100 dark:bg-yellow-900' };
    return { level: 'Low', color: 'text-green-600 dark:text-green-400', bg: 'bg-green-100 dark:bg-green-900' };
  };

  // Extract correlations and IOCs with memoization
  const { correlations, iocs } = useMemo(() => {
    const correlations = [];
    const iocs = {
      ips: new Set(),
      domains: new Set(),
      hashes: new Set(),
      processes: new Set(),
      files: new Set()
    };

    // Process memory data
    if (combinedData.memory?.analysis_results?.processes) {
      combinedData.memory.analysis_results.processes.forEach(process => {
        correlations.push({
          type: 'Process Correlation',
          source: 'Memory Analysis',
          details: `Process ${process.name} (PID: ${process.pid}) detected`,
          severity: process.anomalies?.length > 0 ? 'high' : 'low',
          pid: process.pid,
          name: process.name
        });
        
        iocs.processes.add(process.name);
        if (process.network_artifacts) {
          process.network_artifacts.forEach(conn => {
            iocs.ips.add(conn.remote_address);
          });
        }
      });
    }

    // Process network data
    if (combinedData.network?.network_flows) {
      combinedData.network.network_flows.forEach(flow => {
        if (flow.threat_intel?.dst_reputation === 'malicious') {
          correlations.push({
            type: 'Network IOC Correlation',
            source: 'Network Analysis',
            details: `Malicious connection to ${flow.dst_ip}:${flow.dst_port}`,
            severity: 'critical',
            ip: flow.dst_ip
          });
        }
        
        iocs.ips.add(flow.dst_ip);
        iocs.ips.add(flow.src_ip);
      });
    }

    // Process procmon data
    if (combinedData.procmon?.alerts) {
      combinedData.procmon.alerts.forEach(alert => {
        correlations.push({
          type: 'Process Monitor Alert',
          source: 'Process Monitor',
          details: alert.title,
          severity: alert.severity,
          description: alert.description
        });
      });
    }

    return { correlations, iocs };
  }, [combinedData]);

  const overallRiskScore = combinedData.memory?.threat_assessment?.overall_risk_score || 7.5;
  const riskInfo = getRiskLevel(overallRiskScore);

  return (
    <div className="p-6 space-y-6">
      {/* Executive Summary */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
              Executive Summary
            </h3>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${riskInfo.bg} ${riskInfo.color}`}>
              {riskInfo.level} Risk
            </div>
          </div>
          
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Risk Assessment</h4>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500 dark:text-gray-400">Overall Risk Score</span>
                  <span className={`text-lg font-bold ${riskInfo.color}`}>
                    {overallRiskScore.toFixed(1)}/10
                  </span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                  <div 
                    className={`h-3 rounded-full transition-all duration-500 ${
                      overallRiskScore >= 8 ? 'bg-red-600' :
                      overallRiskScore >= 6 ? 'bg-orange-600' :
                      overallRiskScore >= 4 ? 'bg-yellow-600' :
                      'bg-green-600'
                    }`}
                    style={{ width: `${(overallRiskScore / 10) * 100}%` }}
                  />
                </div>
              </div>
            </div>
            
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Data Sources</h4>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Memory Analysis</span>
                  <span className={`font-medium ${combinedData.memory ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}`}>
                    {combinedData.memory ? 'Available' : 'Not Available'}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Network Analysis</span>
                  <span className={`font-medium ${combinedData.network ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}`}>
                    {combinedData.network ? 'Available' : 'Not Available'}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Process Monitor</span>
                  <span className={`font-medium ${combinedData.procmon ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}`}>
                    {combinedData.procmon ? 'Available' : 'Not Available'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Key Findings */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <LinkIcon className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Total Correlations
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {correlations.length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Critical Findings
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {correlations.filter(c => c.severity === 'critical').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <DocumentTextIcon className="h-6 w-6 text-orange-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Unique IOCs
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {Array.from(iocs.ips).length + Array.from(iocs.processes).length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ChartBarIcon className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Data Sources
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {Object.values(combinedData).filter(Boolean).length}/3
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Cross-Platform Correlations */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
            Cross-Platform Correlations
          </h3>
          <div className="space-y-4">
            {correlations.map((correlation, index) => (
              <div key={index} className={`p-4 border rounded-lg ${
                correlation.severity === 'critical' ? 'border-red-200 dark:border-red-700 bg-red-50 dark:bg-red-900/20' :
                correlation.severity === 'high' ? 'border-orange-200 dark:border-orange-700 bg-orange-50 dark:bg-orange-900/20' :
                'border-blue-200 dark:border-blue-700 bg-blue-50 dark:bg-blue-900/20'
              }`}>
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 mt-1">
                      <LinkIcon className={`h-5 w-5 ${
                        correlation.severity === 'critical' ? 'text-red-600 dark:text-red-400' :
                        correlation.severity === 'high' ? 'text-orange-600 dark:text-orange-400' :
                        'text-blue-600 dark:text-blue-400'
                      }`} />
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                        {correlation.type}
                      </h4>
                      <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                        {correlation.details}
                      </p>
                      {correlation.description && (
                        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                          {correlation.description}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end space-y-2">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      correlation.severity === 'critical' ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200' :
                      correlation.severity === 'high' ? 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200' :
                      'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                    }`}>
                      {correlation.severity}
                    </span>
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {correlation.source}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Indicators of Compromise */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
            Indicators of Compromise (IOCs)
          </h3>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Network Indicators</h4>
              <div className="space-y-2">
                {Array.from(iocs.ips).slice(0, 10).map((ip, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded">
                    <span className="text-sm font-mono text-gray-900 dark:text-white">{ip}</span>
                    <span className="text-xs text-gray-500 dark:text-gray-400">IP Address</span>
                  </div>
                ))}
              </div>
            </div>
            
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Process Indicators</h4>
              <div className="space-y-2">
                {Array.from(iocs.processes).slice(0, 10).map((process, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded">
                    <span className="text-sm font-mono text-gray-900 dark:text-white">{process}</span>
                    <span className="text-xs text-gray-500 dark:text-gray-400">Process Name</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recommendations */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
            Recommended Actions
          </h3>
          <div className="space-y-3">
            {overallRiskScore >= 8 && (
              <div className="flex items-start space-x-3 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-lg">
                <ExclamationTriangleIcon className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-red-800 dark:text-red-200">Immediate Isolation Required</p>
                  <p className="text-sm text-red-700 dark:text-red-300">Isolate affected systems from the network immediately to prevent lateral movement.</p>
                </div>
              </div>
            )}
            
            {correlations.filter(c => c.severity === 'critical').length > 0 && (
              <div className="flex items-start space-x-3 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-700 rounded-lg">
                <ShieldCheckIcon className="h-5 w-5 text-orange-600 dark:text-orange-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-orange-800 dark:text-orange-200">Block Malicious IPs</p>
                  <p className="text-sm text-orange-700 dark:text-orange-300">Block all identified malicious IP addresses at the network perimeter.</p>
                </div>
              </div>
            )}
            
            <div className="flex items-start space-x-3 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded-lg">
              <DocumentTextIcon className="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Enhanced Monitoring</p>
                <p className="text-sm text-blue-700 dark:text-blue-300">Implement enhanced monitoring for all identified processes and network connections.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CombinedReport;
