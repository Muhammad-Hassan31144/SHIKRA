import React, { useState, useMemo, useCallback } from 'react';
import { 
  ResponsiveContainer,
  Treemap,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  PieChart,
  Pie,
  LineChart,
  Line
} from 'recharts';
import {
  ChevronRightIcon,
  ChevronDownIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  CommandLineIcon,
  ClockIcon,
  UserIcon,
  FolderIcon,
  LinkIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

const ProcessTreeVisualization = ({ processData, onProcessSelect }) => {
  const [expandedNodes, setExpandedNodes] = useState(new Set());
  const [selectedNode, setSelectedNode] = useState(null);
  const [viewMode, setViewMode] = useState('tree'); // tree, hierarchy, timeline

  // Build hierarchical process tree from flat events
  const processTree = useMemo(() => {
    if (!processData || !Array.isArray(processData)) return [];

    const processMap = new Map();
    const rootProcesses = [];

    // First pass: create all process nodes
    processData.forEach(event => {
      const pid = event.process_info?.pid;
      const ppid = event.process_info?.ppid;
      const name = event.process_info?.name;
      
      if (!pid || !name) return;

      if (!processMap.has(pid)) {
        processMap.set(pid, {
          id: pid,
          pid,
          ppid,
          name,
          path: event.process_info?.path,
          command_line: event.process_info?.command_line,
          user: event.process_info?.user,
          children: [],
          events: [],
          threat_level: 'low',
          start_time: event.timestamp,
          end_time: null,
          cpu_usage: Math.random() * 100,
          memory_usage: Math.random() * 500,
          network_connections: 0,
          file_operations: 0,
          registry_operations: 0
        });
      }

      const process = processMap.get(pid);
      process.events.push(event);

      // Update threat level based on event severity
      if (event.enrichment?.threat_intel?.severity) {
        const severity = event.enrichment.threat_intel.severity;
        if (severity === 'critical' || severity === 'high') {
          process.threat_level = 'high';
        } else if (severity === 'medium' && process.threat_level === 'low') {
          process.threat_level = 'medium';
        }
      }

      // Count operation types
      switch (event.event_type) {
        case 'network':
          process.network_connections++;
          break;
        case 'file':
          process.file_operations++;
          break;
        case 'registry':
          process.registry_operations++;
          break;
      }
    });

    // Second pass: build hierarchy
    processMap.forEach(process => {
      if (process.ppid && processMap.has(process.ppid)) {
        processMap.get(process.ppid).children.push(process);
      } else {
        rootProcesses.push(process);
      }
    });

    return rootProcesses;
  }, [processData]);

  const toggleNode = useCallback((nodeId) => {
    setExpandedNodes(prev => {
      const newSet = new Set(prev);
      if (newSet.has(nodeId)) {
        newSet.delete(nodeId);
      } else {
        newSet.add(nodeId);
      }
      return newSet;
    });
  }, []);

  const selectNode = useCallback((node) => {
    setSelectedNode(node);
    onProcessSelect?.(node);
  }, [onProcessSelect]);

  const getThreatIcon = (threatLevel) => {
    switch (threatLevel) {
      case 'high':
        return <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />;
      case 'medium':
        return <ShieldExclamationIcon className="h-4 w-4 text-orange-500" />;
      default:
        return <CpuChipIcon className="h-4 w-4 text-green-500" />;
    }
  };

  const getThreatColor = (threatLevel) => {
    switch (threatLevel) {
      case 'high':
        return 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20';
      case 'medium':
        return 'border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-900/20';
      default:
        return 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-900/20';
    }
  };

  const ProcessNode = ({ process, level = 0 }) => {
    const isExpanded = expandedNodes.has(process.id);
    const isSelected = selectedNode?.id === process.id;
    const hasChildren = process.children.length > 0;

    return (
      <div className="mb-2">
        <div
          className={`flex items-center p-3 rounded-lg border-2 cursor-pointer transition-all duration-200 ${
            isSelected
              ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/30'
              : getThreatColor(process.threat_level)
          } hover:shadow-md`}
          style={{ marginLeft: level * 24 }}
          onClick={() => selectNode(process)}
        >
          {/* Expand/Collapse Button */}
          {hasChildren && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                toggleNode(process.id);
              }}
              className="mr-2 p-1 rounded hover:bg-gray-200 dark:hover:bg-gray-600"
            >
              {isExpanded ? (
                <ChevronDownIcon className="h-4 w-4" />
              ) : (
                <ChevronRightIcon className="h-4 w-4" />
              )}
            </button>
          )}

          {/* Process Icon */}
          <div className="mr-3 flex-shrink-0">
            {getThreatIcon(process.threat_level)}
          </div>

          {/* Process Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2">
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white truncate">
                {process.name}
              </h4>
              <span className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 rounded">
                PID: {process.pid}
              </span>
              {process.ppid && (
                <span className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 rounded">
                  PPID: {process.ppid}
                </span>
              )}
            </div>
            
            <p className="text-xs text-gray-500 dark:text-gray-400 truncate mt-1">
              {process.command_line || process.path || 'No command line available'}
            </p>
            
            {/* Process Statistics */}
            <div className="flex items-center space-x-4 mt-2 text-xs text-gray-600 dark:text-gray-300">
              <span className="flex items-center">
                <UserIcon className="h-3 w-3 mr-1" />
                {process.user || 'Unknown'}
              </span>
              <span className="flex items-center">
                <ClockIcon className="h-3 w-3 mr-1" />
                {new Date(process.start_time).toLocaleTimeString()}
              </span>
              <span className="flex items-center">
                <DocumentTextIcon className="h-3 w-3 mr-1" />
                {process.file_operations} files
              </span>
              <span className="flex items-center">
                <LinkIcon className="h-3 w-3 mr-1" />
                {process.network_connections} net
              </span>
            </div>

            {/* Activity Indicators */}
            <div className="flex items-center space-x-2 mt-2">
              {process.events.length > 0 && (
                <span className="px-2 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">
                  {process.events.length} events
                </span>
              )}
              {process.threat_level !== 'low' && (
                <span className={`px-2 py-1 text-xs rounded ${
                  process.threat_level === 'high' 
                    ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                    : 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200'
                }`}>
                  {process.threat_level} risk
                </span>
              )}
            </div>
          </div>

          {/* Resource Usage */}
          <div className="flex flex-col items-end space-y-1 text-xs">
            <div className="flex items-center space-x-2">
              <span className="text-gray-500">CPU:</span>
              <span className="font-mono">{process.cpu_usage.toFixed(1)}%</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-gray-500">MEM:</span>
              <span className="font-mono">{process.memory_usage.toFixed(1)}MB</span>
            </div>
          </div>
        </div>

        {/* Render Children */}
        {hasChildren && isExpanded && (
          <div className="mt-2">
            {process.children.map(child => (
              <ProcessNode key={child.id} process={child} level={level + 1} />
            ))}
          </div>
        )}
      </div>
    );
  };

  // Tree visualization data for D3-like charts
  const treeData = useMemo(() => {
    const convertToTreeData = (processes) => {
      return processes.map(process => ({
        name: process.name,
        value: process.events.length,
        children: process.children.length > 0 ? convertToTreeData(process.children) : undefined,
        threat_level: process.threat_level,
        pid: process.pid
      }));
    };
    return convertToTreeData(processTree);
  }, [processTree]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className='p-3 rounded-lg shadow-lg border 
            dark:bg-gray-800 dark:border-gray-600 dark:text-white
          bg-white border-gray-200 text-gray-900'
        >
          <p className="font-medium">{data.name}</p>
          <p className="text-sm">PID: {data.pid}</p>
          <p className="text-sm">Events: {data.value}</p>
          <p className="text-sm">Threat: {data.threat_level}</p>
        </div>
      );
    }
    return null;
  };

  if (!processTree.length) {
    return (
      <div className="text-center py-8">
        <CpuChipIcon className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No Process Tree Available</h3>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Process hierarchy will appear here when process events are captured.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* View Mode Selector */}
      <div className="flex space-x-2 bg-gray-100 dark:bg-gray-700 p-1 rounded-lg">
        {[
          { key: 'tree', label: 'Tree View', icon: CpuChipIcon },
          { key: 'hierarchy', label: 'Hierarchy Chart', icon: FolderIcon },
          { key: 'timeline', label: 'Timeline View', icon: ClockIcon }
        ].map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setViewMode(key)}
            className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
              viewMode === key
                ? 'bg-white dark:bg-gray-600 text-blue-600 dark:text-blue-400 shadow'
                : 'text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <Icon className="h-4 w-4 mr-2" />
            {label}
          </button>
        ))}
      </div>

      {/* Process Tree Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Root Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processTree.length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">High Risk Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processTree.reduce((acc, p) => acc + (p.threat_level === 'high' ? 1 : 0) + 
                  p.children.reduce((childAcc, c) => childAcc + (c.threat_level === 'high' ? 1 : 0), 0), 0)}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border">
          <div className="flex items-center">
            <FolderIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Child Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processTree.reduce((acc, p) => acc + p.children.length, 0)}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border">
          <div className="flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Events</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processTree.reduce((acc, p) => acc + p.events.length + 
                  p.children.reduce((childAcc, c) => childAcc + c.events.length, 0), 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Visualization */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        {viewMode === 'tree' && (
          <div className="p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Process Tree Hierarchy
            </h3>
            <div className="max-h-96 overflow-y-auto">
              {processTree.map(process => (
                <ProcessNode key={process.id} process={process} />
              ))}
            </div>
          </div>
        )}

        {viewMode === 'hierarchy' && (
          <div className="p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Process Hierarchy Chart
            </h3>
            <div className="h-96">
              <ResponsiveContainer width="100%" height="100%">
                <Treemap
                  data={treeData}
                  dataKey="value"
                  aspectRatio={4/3}
                  stroke="#fff"
                  fill="#8884d8"
                >
                  <Tooltip content={<CustomTooltip />} />
                </Treemap>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {viewMode === 'timeline' && (
          <div className="p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Process Timeline
            </h3>
            <div className="space-y-4 max-h-96 overflow-y-auto">
              {processTree
                .flatMap(p => [p, ...p.children])
                .sort((a, b) => new Date(a.start_time) - new Date(b.start_time))
                .map((process, index) => (
                  <div
                    key={process.id}
                    className={`flex items-center p-3 rounded border cursor-pointer transition-colors ${
                      getThreatColor(process.threat_level)
                    } hover:shadow-md`}
                    onClick={() => selectNode(process)}
                  >
                    <div className="flex-shrink-0 mr-4">
                      <div className="w-2 h-2 rounded-full bg-blue-500"></div>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-gray-900 dark:text-white">
                          {process.name}
                        </span>
                        <span className="text-sm text-gray-500">
                          {new Date(process.start_time).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300 truncate">
                        PID {process.pid} • {process.events.length} events • {process.threat_level} risk
                      </p>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>

      {/* Selected Process Details */}
      {selectedNode && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Process Details: {selectedNode.name}
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">Process Information</h4>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-500">Process ID:</dt>
                  <dd className="text-gray-900 dark:text-white font-mono">{selectedNode.pid}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Parent PID:</dt>
                  <dd className="text-gray-900 dark:text-white font-mono">{selectedNode.ppid || 'N/A'}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">User:</dt>
                  <dd className="text-gray-900 dark:text-white">{selectedNode.user || 'Unknown'}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Threat Level:</dt>
                  <dd className={`font-medium ${
                    selectedNode.threat_level === 'high' ? 'text-red-600' :
                    selectedNode.threat_level === 'medium' ? 'text-orange-600' : 'text-green-600'
                  }`}>
                    {selectedNode.threat_level.toUpperCase()}
                  </dd>
                </div>
              </dl>
            </div>
            
            <div>
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">Activity Summary</h4>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-500">Total Events:</dt>
                  <dd className="text-gray-900 dark:text-white">{selectedNode.events.length}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">File Operations:</dt>
                  <dd className="text-gray-900 dark:text-white">{selectedNode.file_operations}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Network Connections:</dt>
                  <dd className="text-gray-900 dark:text-white">{selectedNode.network_connections}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Registry Operations:</dt>
                  <dd className="text-gray-900 dark:text-white">{selectedNode.registry_operations}</dd>
                </div>
              </dl>
            </div>
          </div>
          
          {selectedNode.command_line && (
            <div className="mt-4">
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">Command Line</h4>
              <code className="block p-3 bg-gray-100 dark:bg-gray-700 rounded text-sm text-gray-900 dark:text-white overflow-x-auto">
                {selectedNode.command_line}
              </code>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ProcessTreeVisualization;
