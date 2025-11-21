import React from 'react';
import {
  LightBulbIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ClockIcon,
  FlagIcon
} from '@heroicons/react/24/outline';

const MemoryRecommendations = ({ memoryData }) => {
  const recommendations = memoryData?.recommendations || [];

  const getPriorityBadge = (priority) => {
    const badges = {
      'immediate': { 
        color: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200', 
        icon: ExclamationTriangleIcon,
        label: 'IMMEDIATE'
      },
      'high': { 
        color: 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200', 
        icon: FlagIcon,
        label: 'HIGH'
      },
      'medium': { 
        color: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200', 
        icon: ClockIcon,
        label: 'MEDIUM'
      },
      'low': { 
        color: 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200', 
        icon: LightBulbIcon,
        label: 'LOW'
      }
    };
    return badges[priority] || badges.low;
  };

  const getActionDescription = (action, target) => {
    const descriptions = {
      'isolate_system': {
        title: 'Isolate System',
        description: 'Immediately disconnect the affected system from the network to prevent lateral movement and data exfiltration.',
        steps: [
          'Disconnect network cables or disable network adapters',
          'Preserve system state for forensic analysis',
          'Document current system status',
          'Notify incident response team'
        ]
      },
      'block_c2_ip': {
        title: 'Block C2 Communication',
        description: 'Block malicious command and control server communications at network perimeter.',
        steps: [
          `Add firewall rule to block ${target || 'malicious IP'}`,
          'Update network security appliances',
          'Monitor for connection attempts',
          'Update threat intelligence feeds'
        ]
      },
      'remove_persistence': {
        title: 'Remove Persistence Mechanism',
        description: 'Remove malware persistence mechanisms to prevent automatic restart.',
        steps: [
          `Delete registry key: ${target || 'persistence key'}`,
          'Verify removal was successful',
          'Check for additional persistence methods',
          'Monitor for recreation attempts'
        ]
      },
      'quarantine_file': {
        title: 'Quarantine Malicious File',
        description: 'Isolate and remove malicious files from the system.',
        steps: [
          `Quarantine file: ${target || 'malicious file'}`,
          'Update antivirus signatures',
          'Scan for additional instances',
          'Verify file removal'
        ]
      },
      'terminate_process': {
        title: 'Terminate Malicious Process',
        description: 'Stop execution of malicious processes and prevent restart.',
        steps: [
          `Terminate process: ${target || 'malicious process'}`,
          'Remove associated files',
          'Check for child processes',
          'Monitor for process recreation'
        ]
      },
      'patch_vulnerability': {
        title: 'Patch System Vulnerability',
        description: 'Apply security patches to close exploited vulnerabilities.',
        steps: [
          'Identify required security patches',
          'Test patches in staging environment',
          'Apply patches during maintenance window',
          'Verify patch installation'
        ]
      },
      'update_signatures': {
        title: 'Update Security Signatures',
        description: 'Update antivirus and security tool signatures to detect new threats.',
        steps: [
          'Update antivirus signatures',
          'Update IDS/IPS rules',
          'Update firewall rules',
          'Perform full system scan'
        ]
      },
      'forensic_analysis': {
        title: 'Conduct Forensic Analysis',
        description: 'Perform detailed forensic analysis to understand attack scope.',
        steps: [
          'Create forensic image of system',
          'Analyze memory dumps',
          'Review system logs',
          'Document findings'
        ]
      }
    };
    
    return descriptions[action] || {
      title: action.replace('_', ' ').toUpperCase(),
      description: 'Follow standard incident response procedures for this action.',
      steps: ['Execute recommended action', 'Document results', 'Monitor for effectiveness']
    };
  };

  if (recommendations.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8">
        <div className="text-center">
          <ShieldCheckIcon className="mx-auto h-12 w-12 text-green-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No Immediate Actions Required</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            The memory analysis did not identify any immediate security actions needed.
          </p>
        </div>
      </div>
    );
  }

  // Sort recommendations by priority
  const sortedRecommendations = [...recommendations].sort((a, b) => {
    const priorityOrder = { 'immediate': 4, 'high': 3, 'medium': 2, 'low': 1 };
    return (priorityOrder[b.priority] || 0) - (priorityOrder[a.priority] || 0);
  });

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Immediate</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {recommendations.filter(r => r.priority === 'immediate').length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <FlagIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">High Priority</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {recommendations.filter(r => r.priority === 'high').length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ClockIcon className="h-8 w-8 text-yellow-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Medium Priority</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {recommendations.filter(r => r.priority === 'medium').length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <LightBulbIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Actions</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{recommendations.length}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recommendations List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-6">
          <LightBulbIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Security Recommendations</h3>
        </div>
        
        <div className="space-y-6">
          {sortedRecommendations.map((recommendation, index) => {
            const priorityBadge = getPriorityBadge(recommendation.priority);
            const IconComponent = priorityBadge.icon;
            const actionDetails = getActionDescription(recommendation.action, recommendation.target);
            
            return (
              <div key={index} className={`border rounded-lg p-6 ${
                recommendation.priority === 'immediate' 
                  ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' 
                  : recommendation.priority === 'high'
                  ? 'border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-900/20'
                  : recommendation.priority === 'medium'
                  ? 'border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20'
                  : 'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20'
              }`}>
                <div className="flex items-start space-x-4">
                  <div className={`flex-shrink-0 h-12 w-12 rounded-full flex items-center justify-center ${
                    recommendation.priority === 'immediate' ? 'bg-red-100 dark:bg-red-900' :
                    recommendation.priority === 'high' ? 'bg-orange-100 dark:bg-orange-900' :
                    recommendation.priority === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900' :
                    'bg-blue-100 dark:bg-blue-900'
                  }`}>
                    <IconComponent className={`h-6 w-6 ${
                      recommendation.priority === 'immediate' ? 'text-red-600 dark:text-red-400' :
                      recommendation.priority === 'high' ? 'text-orange-600 dark:text-orange-400' :
                      recommendation.priority === 'medium' ? 'text-yellow-600 dark:text-yellow-400' :
                      'text-blue-600 dark:text-blue-400'
                    }`} />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3 mb-2">
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white">
                        {actionDetails.title}
                      </h4>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${priorityBadge.color}`}>
                        <IconComponent className="h-3 w-3 mr-1" />
                        {priorityBadge.label}
                      </span>
                    </div>
                    
                    <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                      {actionDetails.description}
                    </p>

                    {/* Rationale */}
                    <div className="mb-4 p-3 bg-white dark:bg-gray-700 rounded-lg border border-gray-200 dark:border-gray-600">
                      <h5 className="font-medium text-gray-900 dark:text-white mb-1">Rationale</h5>
                      <p className="text-sm text-gray-600 dark:text-gray-300">
                        {recommendation.rationale}
                      </p>
                      {recommendation.target && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono">
                          Target: {recommendation.target}
                        </p>
                      )}
                    </div>

                    {/* Action Steps */}
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white mb-2">Recommended Steps</h5>
                      <ol className="list-decimal list-inside space-y-1 text-sm text-gray-600 dark:text-gray-300">
                        {actionDetails.steps.map((step, stepIndex) => (
                          <li key={stepIndex}>{step}</li>
                        ))}
                      </ol>
                    </div>

                    {/* Urgency Indicator */}
                    {recommendation.priority === 'immediate' && (
                      <div className="mt-4 p-3 bg-red-100 dark:bg-red-900/30 rounded-lg border border-red-200 dark:border-red-800">
                        <div className="flex items-center">
                          <ExclamationTriangleIcon className="h-5 w-5 text-red-600 dark:text-red-400 mr-2" />
                          <span className="text-sm font-medium text-red-800 dark:text-red-200">
                            IMMEDIATE ACTION REQUIRED - Execute within the next hour
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* General Security Notes */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
        <div className="flex items-start space-x-3">
          <ShieldCheckIcon className="h-6 w-6 text-blue-600 dark:text-blue-400 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">Additional Security Considerations</h4>
            <ul className="text-sm text-blue-700 dark:text-blue-300 space-y-1">
              <li>• Document all actions taken for incident response records</li>
              <li>• Monitor system behavior after implementing recommendations</li>
              <li>• Consider threat hunting activities to identify similar compromises</li>
              <li>• Update security procedures based on lessons learned</li>
              <li>• Coordinate with incident response team for complex actions</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MemoryRecommendations;
