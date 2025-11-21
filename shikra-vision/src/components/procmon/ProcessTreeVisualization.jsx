import React, { useState } from 'react';
import {
  CpuChipIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  PlayIcon,
  StopIcon,
  ExclamationTriangleIcon,
  UserIcon,
  ClockIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

const ProcessTreeVisualization = ({ procmonData }) => {
  const [expandedNodes, setExpandedNodes] = useState(new Set());
  const [selectedProcess, setSelectedProcess] = useState(null);
  
  const processTree = procmonData?.process_tree || {};
  const processes = processTree.processes || [];
  const relationships = processTree.relationships || [];

  // Build hierarchical tree structure
  const buildTree = () => {
    const processMap = new Map();
    const rootProcesses = [];

    // Create process nodes
    processes.forEach(process => {
      processMap.set(process.pid, {
        ...process,
        children: []
      });
    });

    // Build parent-child relationships
    relationships.forEach(rel => {
      const parent = processMap.get(rel.parent_pid);
      const child = processMap.get(rel.child_pid);
      
      if (parent && child) {
        parent.children.push(child);
      }
    });

    // Find root processes (those without parents in relationships)
    const childPids = new Set(relationships.map(rel => rel.child_pid));
    processes.forEach(process => {
      if (!childPids.has(process.pid)) {
        const processNode = processMap.get(process.pid);
        if (processNode) {
          rootProcesses.push(processNode);
        }
      }
    });

    return rootProcesses;
  };

  const toggleExpanded = (pid) => {
    const newExpanded = new Set(expandedNodes);
    if (newExpanded.has(pid)) {
      newExpanded.delete(pid);
    } else {
      newExpanded.add(pid);
    }
    setExpandedNodes(newExpanded);
  };

  const getProcessIcon = (process) => {
    if (process.is_system) {
      return <CpuChipIcon className="h-5 w-5 text-blue-500" />;
    }
    if (process.integrity_level === 'High' || process.integrity_level === 'System') {
      return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
    }
    return <UserIcon className="h-5 w-5 text-green-500" />;
  };

  const getIntegrityColor = (level) => {
    switch (level) {
      case 'System':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300';
      case 'High':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-300';
      case 'Medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300';
      case 'Low':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const ProcessNode = ({ process, depth = 0 }) => {
    const hasChildren = process.children && process.children.length > 0;
    const isExpanded = expandedNodes.has(process.pid);
    const paddingLeft = depth * 24;

    return (
      <div>
        <div 
          className={`flex items-center p-3 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer border-l-2 ${
            selectedProcess?.pid === process.pid 
              ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' 
              : 'border-transparent'
          }`}
          style={{ paddingLeft: `${paddingLeft + 12}px` }}
          onClick={() => setSelectedProcess(process)}
        >
          {hasChildren && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                toggleExpanded(process.pid);
              }}
              className="mr-2 p-1 hover:bg-gray-200 dark:hover:bg-gray-600 rounded"
            >
              {isExpanded ? (
                <ChevronDownIcon className="h-4 w-4 text-gray-500" />
              ) : (
                <ChevronRightIcon className="h-4 w-4 text-gray-500" />
              )}
            </button>
          )}
          
          {!hasChildren && <div className="w-6 mr-2" />}
          
          <div className="flex items-center space-x-3 flex-1 min-w-0">
            {getProcessIcon(process)}
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center space-x-2">
                <span className="font-medium text-gray-900 dark:text-white truncate">
                  {process.process_name || 'Unknown'}
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                  [{process.pid}]
                </span>
                {process.integrity_level && (
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${getIntegrityColor(process.integrity_level)}`}>
                    {process.integrity_level}
                  </span>
                )}
              </div>
              
              <div className="flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400 mt-1">
                <span>User: {process.user || 'Unknown'}</span>
                {process.create_time && (
                  <span>Started: {new Date(process.create_time).toLocaleString()}</span>
                )}
                {process.command_line && (
                  <span className="truncate max-w-xs" title={process.command_line}>
                    CMD: {process.command_line}
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
        
        {hasChildren && isExpanded && (
          <div>
            {process.children.map(child => (
              <ProcessNode 
                key={child.pid} 
                process={child} 
                depth={depth + 1} 
              />
            ))}
          </div>
        )}
      </div>
    );
  };

  const tree = buildTree();

  return (
    <div className="space-y-6">
      {/* Process Tree Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processes.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <PlayIcon className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Active Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processes.filter(p => !p.exit_time).length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <StopIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Terminated</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processes.filter(p => p.exit_time).length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">High Privilege</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {processes.filter(p => p.integrity_level === 'High' || p.integrity_level === 'System').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Process Tree */}
        <div className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <CpuChipIcon className="h-6 w-6 text-blue-500 mr-2" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Process Tree</h3>
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {tree.length} root process{tree.length !== 1 ? 'es' : ''}
              </div>
            </div>
          </div>
          
          <div className="max-h-96 overflow-y-auto">
            {tree.length > 0 ? (
              tree.map(process => (
                <ProcessNode key={process.pid} process={process} />
              ))
            ) : (
              <div className="p-6 text-center text-gray-500 dark:text-gray-400">
                No process tree data available
              </div>
            )}
          </div>
        </div>

        {/* Process Details */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <DocumentTextIcon className="h-6 w-6 text-green-500 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Process Details</h3>
            </div>
          </div>
          
          <div className="p-6">
            {selectedProcess ? (
              <div className="space-y-4">
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Process Name</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
                    {selectedProcess.process_name || 'Unknown'}
                  </dd>
                </div>

                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Process ID</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
                    {selectedProcess.pid}
                  </dd>
                </div>

                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Parent PID</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono">
                    {selectedProcess.parent_pid || 'N/A'}
                  </dd>
                </div>

                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">User</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                    {selectedProcess.user || 'Unknown'}
                  </dd>
                </div>

                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Integrity Level</dt>
                  <dd className="mt-1">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getIntegrityColor(selectedProcess.integrity_level)}`}>
                      {selectedProcess.integrity_level || 'Unknown'}
                    </span>
                  </dd>
                </div>

                {selectedProcess.create_time && (
                  <div>
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Creation Time</dt>
                    <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                      {new Date(selectedProcess.create_time).toLocaleString()}
                    </dd>
                  </div>
                )}

                {selectedProcess.exit_time && (
                  <div>
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Exit Time</dt>
                    <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                      {new Date(selectedProcess.exit_time).toLocaleString()}
                    </dd>
                  </div>
                )}

                {selectedProcess.command_line && (
                  <div>
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Command Line</dt>
                    <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono bg-gray-50 dark:bg-gray-700 p-2 rounded break-all">
                      {selectedProcess.command_line}
                    </dd>
                  </div>
                )}

                {selectedProcess.image_path && (
                  <div>
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Image Path</dt>
                    <dd className="mt-1 text-sm text-gray-900 dark:text-white font-mono break-all">
                      {selectedProcess.image_path}
                    </dd>
                  </div>
                )}

                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Status</dt>
                  <div className="flex items-center space-x-2">
                    {selectedProcess.exit_time ? (
                      <>
                        <StopIcon className="h-5 w-5 text-red-500" />
                        <span className="text-sm text-red-600 dark:text-red-400">Terminated</span>
                      </>
                    ) : (
                      <>
                        <PlayIcon className="h-5 w-5 text-green-500" />
                        <span className="text-sm text-green-600 dark:text-green-400">Running</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-500 dark:text-gray-400">
                <CpuChipIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
                <p>Select a process from the tree to view details</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProcessTreeVisualization;
