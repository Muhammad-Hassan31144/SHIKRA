import React from 'react';
import useCyberStore from '../store/cyberStore';
import { 
  CpuChipIcon, 
  ExclamationTriangleIcon,
  ShieldExclamationIcon 
} from '@heroicons/react/24/outline';

const ProcessTree = () => {
  const { threatData, setSelectedProcess } = useCyberStore();
  const processes = threatData.memory?.analysis_results?.processes || [];

  const getSeverityColor = (anomalies) => {
    if (!anomalies || anomalies.length === 0) return 'text-green-600';
    
    const hasCritical = anomalies.some(a => a.severity === 'critical');
    const hasHigh = anomalies.some(a => a.severity === 'high');
    
    if (hasCritical) return 'text-red-600';
    if (hasHigh) return 'text-orange-600';
    return 'text-yellow-600';
  };

  const getProcessIcon = (anomalies) => {
    const severity = getSeverityColor(anomalies);
    if (severity === 'text-red-600') {
      return <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />;
    }
    if (severity === 'text-orange-600') {
      return <ShieldExclamationIcon className="h-5 w-5 text-orange-600" />;
    }
    return <CpuChipIcon className="h-5 w-5 text-green-600" />;
  };

  const formatMemory = (bytes) => {
    if (!bytes) return 'N/A';
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(1)} MB`;
  };

  const truncateCommand = (command, maxLength = 50) => {
    if (!command) return 'N/A';
    return command.length > maxLength ? 
      `${command.substring(0, maxLength)}...` : 
      command;
  };

  return (
    <div className="bg-white shadow rounded-lg">
      <div className="px-4 py-5 sm:p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg leading-6 font-medium text-gray-900">
            Process Analysis
          </h3>
          <CpuChipIcon className="h-5 w-5 text-gray-400" />
        </div>

        <div className="space-y-3">
          {processes.map((process, index) => (
            <div
              key={process.pid || index}
              className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 cursor-pointer transition-colors"
              onClick={() => setSelectedProcess(process)}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  {getProcessIcon(process.anomalies)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {process.name}
                      </p>
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                        PID: {process.pid}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 truncate mt-1">
                      {truncateCommand(process.command_line)}
                    </p>
                    <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                      <span>User: {process.user || 'N/A'}</span>
                      <span>Session: {process.session_id || 'N/A'}</span>
                      {process.vad_info?.private_memory && (
                        <span>Memory: {formatMemory(process.vad_info.private_memory)}</span>
                      )}
                    </div>
                  </div>
                </div>
                
                {/* Anomaly Indicators */}
                <div className="flex flex-col items-end space-y-1">
                  {process.anomalies?.map((anomaly, anomalyIndex) => (
                    <span
                      key={anomalyIndex}
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                        anomaly.severity === 'critical' ? 'bg-red-100 text-red-800' :
                        anomaly.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}
                    >
                      {anomaly.type}
                    </span>
                  ))}
                </div>
              </div>

              {/* Network Artifacts */}
              {process.network_artifacts?.length > 0 && (
                <div className="mt-3 pt-3 border-t border-gray-100">
                  <p className="text-xs text-gray-500 mb-2">Network Connections:</p>
                  {process.network_artifacts.slice(0, 2).map((conn, connIndex) => (
                    <div key={connIndex} className="flex items-center justify-between text-xs">
                      <span className="text-gray-600">
                        {conn.remote_address}:{conn.remote_port}
                      </span>
                      <span className={`px-2 py-0.5 rounded ${
                        conn.geoip?.threat_categories?.length > 0 ? 
                        'bg-red-100 text-red-800' : 
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {conn.geoip?.country_code || 'Unknown'}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Process Ancestry */}
              {process.process_ancestry?.length > 0 && (
                <div className="mt-3 pt-3 border-t border-gray-100">
                  <p className="text-xs text-gray-500 mb-1">Parent Process:</p>
                  <p className="text-xs text-gray-600">
                    {process.process_ancestry[0]?.name} (PID: {process.process_ancestry[0]?.pid})
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>

        {processes.length === 0 && (
          <div className="text-center py-8">
            <CpuChipIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No processes analyzed</h3>
            <p className="mt-1 text-sm text-gray-500">
              Process analysis data will appear here when available.
            </p>
          </div>
        )}

        {/* Process Statistics */}
        {processes.length > 0 && (
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <h4 className="text-sm font-medium text-gray-900 mb-2">Analysis Summary</h4>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500">Total Processes:</span>
                <span className="ml-2 font-medium">{processes.length}</span>
              </div>
              <div>
                <span className="text-gray-500">With Anomalies:</span>
                <span className="ml-2 font-medium text-red-600">
                  {processes.filter(p => p.anomalies?.length > 0).length}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Network Active:</span>
                <span className="ml-2 font-medium">
                  {processes.filter(p => p.network_artifacts?.length > 0).length}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Unsigned:</span>
                <span className="ml-2 font-medium text-orange-600">
                  {processes.filter(p => 
                    p.anomalies?.some(a => a.type === 'unsigned_executable')
                  ).length}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProcessTree;
