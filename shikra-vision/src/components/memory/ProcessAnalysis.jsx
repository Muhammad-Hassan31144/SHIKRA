import React, { useMemo } from 'react';
import {
  CpuChipIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  UserIcon,
  ClockIcon,
  ChevronDownIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const ProcessAnalysis = ({ memoryData }) => {
  const [expandedProcess, setExpandedProcess] = React.useState(null);
  const processes = memoryData?.analysis_results?.processes || [];

  // Process statistics
  const processStats = useMemo(() => {
    const totalProcesses = processes.length;
    const suspiciousProcesses = processes.filter(p => 
      p.anomalies && p.anomalies.length > 0
    ).length;
    const maliciousProcesses = processes.filter(p => 
      p.anomalies && p.anomalies.some(a => a.severity === 'critical' || a.severity === 'high')
    ).length;
    const avgMemoryUsage = processes.length > 0 
      ? processes.reduce((acc, p) => acc + (p.vad_info?.private_memory || 0), 0) / processes.length 
      : 0;

    return {
      totalProcesses,
      suspiciousProcesses,
      maliciousProcesses,
      avgMemoryUsage: (avgMemoryUsage / (1024 * 1024)).toFixed(1) // Convert to MB
    };
  }, [processes]);

  // Chart data for process resource usage
  const resourceData = useMemo(() => {
    return processes.slice(0, 10).map(proc => ({
      name: proc.name ? proc.name.split('.')[0] : `PID ${proc.pid}`,
      memory: (proc.vad_info?.private_memory || 0) / (1024 * 1024), // Convert to MB
      vads: proc.vad_info?.vad_count || 0,
      threads: proc.threads?.length || 0,
      handles: proc.handles?.length || 0
    }));
  }, [processes]);

  // Threat distribution data
  const threatData = useMemo(() => {
    const critical = processes.filter(p => p.anomalies?.some(a => a.severity === 'critical')).length;
    const high = processes.filter(p => p.anomalies?.some(a => a.severity === 'high')).length;
    const medium = processes.filter(p => p.anomalies?.some(a => a.severity === 'medium')).length;
    const low = processes.filter(p => p.anomalies?.some(a => a.severity === 'low')).length;
    const clean = processes.length - critical - high - medium - low;

    return [
      { name: 'Critical', value: critical, color: '#DC2626' },
      { name: 'High', value: high, color: '#EA580C' },
      { name: 'Medium', value: medium, color: '#D97706' },
      { name: 'Low', value: low, color: '#65A30D' },
      { name: 'Clean', value: clean, color: '#059669' }
    ].filter(item => item.value > 0);
  }, [processes]);

  const getSeverityBadge = (anomalies) => {
    if (!anomalies || anomalies.length === 0) return 'clean';
    const maxSeverity = Math.max(
      ...anomalies.map(a => {
        switch(a.severity) {
          case 'critical': return 4;
          case 'high': return 3;
          case 'medium': return 2;
          case 'low': return 1;
          default: return 0;
        }
      })
    );
    
    switch(maxSeverity) {
      case 4: return 'critical';
      case 3: return 'high';
      case 2: return 'medium';
      case 1: return 'low';
      default: return 'clean';
    }
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white dark:bg-gray-800 p-3 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg">
          <p className="font-medium text-gray-900 dark:text-white">{`${label}`}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }}>
              {`${entry.dataKey}: ${entry.value}`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{processStats.totalProcesses}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Suspicious</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{processStats.suspiciousProcesses}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ChartBarIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{processStats.maliciousProcesses}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ChartBarIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Avg Memory</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{processStats.avgMemoryUsage} MB</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Resource Usage Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top Processes by Memory Usage</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={resourceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                <XAxis 
                  dataKey="name" 
                  stroke="#6B7280"
                  fontSize={11}
                  angle={-45}
                  textAnchor="end"
                  height={80}
                />
                <YAxis stroke="#6B7280" fontSize={12} />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                <Bar dataKey="memory" fill="#3B82F6" name="Memory (MB)" />
                <Bar dataKey="vads" fill="#10B981" name="VADs" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Process Threat Distribution</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={threatData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {threatData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Process List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Process Analysis</h3>
        <div className="space-y-2">
          {processes.map((process, index) => {
            const severity = getSeverityBadge(process.anomalies);
            const isExpanded = expandedProcess === index;
            
            return (
              <div key={index} className="border border-gray-200 dark:border-gray-600 rounded-lg">
                <div 
                  className="p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700"
                  onClick={() => setExpandedProcess(isExpanded ? null : index)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                        severity === 'critical' ? 'bg-red-100 dark:bg-red-900' :
                        severity === 'high' ? 'bg-orange-100 dark:bg-orange-900' :
                        severity === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900' :
                        severity === 'low' ? 'bg-blue-100 dark:bg-blue-900' :
                        'bg-green-100 dark:bg-green-900'
                      }`}>
                        {severity === 'critical' || severity === 'high' ? (
                          <ExclamationTriangleIcon className="h-6 w-6 text-red-600 dark:text-red-400" />
                        ) : (
                          <CpuChipIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center space-x-3">
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {process.name}
                          </span>
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            PID: {process.pid}
                          </span>
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            severity === 'critical' ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200' :
                            severity === 'high' ? 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200' :
                            severity === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200' :
                            severity === 'low' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                            'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                          }`}>
                            {severity}
                          </span>
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400 max-w-md truncate">
                          {process.command_line || process.executable_path || 'No command line available'}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className="text-sm text-gray-900 dark:text-white">
                          {process.vad_info?.private_memory 
                            ? `${(process.vad_info.private_memory / (1024 * 1024)).toFixed(1)} MB`
                            : 'N/A'
                          }
                        </div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          Memory Usage
                        </div>
                      </div>
                      {isExpanded ? (
                        <ChevronDownIcon className="h-5 w-5 text-gray-400" />
                      ) : (
                        <ChevronRightIcon className="h-5 w-5 text-gray-400" />
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-4 pb-4 border-t border-gray-200 dark:border-gray-600">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-4">
                      {/* Basic Info */}
                      <div>
                        <h5 className="font-medium text-gray-900 dark:text-white mb-2">Basic Information</h5>
                        <div className="space-y-1 text-sm">
                          <div><span className="text-gray-500 dark:text-gray-400">PPID:</span> {process.ppid}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">User:</span> {process.user || 'N/A'}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">Session ID:</span> {process.session_id}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">Integrity:</span> {process.integrity_level || 'N/A'}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">Create Time:</span> {process.create_time ? new Date(process.create_time).toLocaleString() : 'N/A'}</div>
                        </div>
                      </div>

                      {/* Memory Info */}
                      <div>
                        <h5 className="font-medium text-gray-900 dark:text-white mb-2">Memory Details</h5>
                        <div className="space-y-1 text-sm">
                          <div><span className="text-gray-500 dark:text-gray-400">VAD Count:</span> {process.vad_info?.vad_count || 0}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">Executable VADs:</span> {process.vad_info?.executable_vads || 0}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">Threads:</span> {process.threads?.length || 0}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">Handles:</span> {process.handles?.length || 0}</div>
                          <div><span className="text-gray-500 dark:text-gray-400">DLLs:</span> {process.dll_list?.length || 0}</div>
                        </div>
                      </div>

                      {/* Anomalies */}
                      <div>
                        <h5 className="font-medium text-gray-900 dark:text-white mb-2">Anomalies</h5>
                        <div className="space-y-2">
                          {process.anomalies && process.anomalies.length > 0 ? 
                            process.anomalies.map((anomaly, anomalyIndex) => (
                              <div key={anomalyIndex} className={`p-2 rounded text-xs ${
                                anomaly.severity === 'critical' ? 'bg-red-50 dark:bg-red-900 text-red-800 dark:text-red-200' :
                                anomaly.severity === 'high' ? 'bg-orange-50 dark:bg-orange-900 text-orange-800 dark:text-orange-200' :
                                anomaly.severity === 'medium' ? 'bg-yellow-50 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200' :
                                'bg-blue-50 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                              }`}>
                                <div className="font-medium">{anomaly.type}</div>
                                <div>{anomaly.description}</div>
                              </div>
                            )) :
                            <div className="text-sm text-gray-500 dark:text-gray-400">No anomalies detected</div>
                          }
                        </div>
                      </div>
                    </div>

                    {/* Network Artifacts */}
                    {process.network_artifacts && process.network_artifacts.length > 0 && (
                      <div className="mt-4">
                        <h5 className="font-medium text-gray-900 dark:text-white mb-2">Network Connections</h5>
                        <div className="space-y-2">
                          {process.network_artifacts.map((conn, connIndex) => (
                            <div key={connIndex} className="p-2 bg-gray-50 dark:bg-gray-700 rounded text-sm">
                              <div className="flex justify-between">
                                <span className="font-mono">{conn.local_address}:{conn.local_port} → {conn.remote_address}:{conn.remote_port}</span>
                                <span className="text-gray-500 dark:text-gray-400">{conn.connection_type?.toUpperCase()}</span>
                              </div>
                              {conn.geoip && (
                                <div className="text-xs text-gray-600 dark:text-gray-300 mt-1">
                                  {conn.geoip.country} ({conn.geoip.organization})
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
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

export default ProcessAnalysis;
