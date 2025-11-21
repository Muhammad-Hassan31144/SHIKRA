import React, { useState } from 'react';
import Layout from '../components/Layout';
import useCyberStore from '../store/cyberStore';
import {
  CpuChipIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  ChartBarIcon,
  Cog6ToothIcon,
  ShieldExclamationIcon,
  PlayIcon
} from '@heroicons/react/24/outline';

// Import ProcMon components
import ProcmonMetadata from '../components/procmon/ProcmonMetadata';
import EventAnalysis from '../components/procmon/EventAnalysis';
import ProcessTreeVisualization from '../components/procmon/ProcessTreeVisualization';
import AggregationSummary from '../components/procmon/AggregationSummary';
import AlertDashboard from '../components/procmon/AlertDashboard';
import ProcmonTimeline from '../components/procmon/ProcmonTimeline';

const ProcessMonitor = () => {
  const { threatData } = useCyberStore();
  const [activeTab, setActiveTab] = useState('overview');

  // Extract ProcMon data from store
  const procmonData = threatData?.procmon || {};
  const metadata = procmonData.metadata || {};
  const events = procmonData.events || [];
  const processTree = procmonData.process_tree || {};
  const aggregations = procmonData.aggregations || {};
  const alerts = procmonData.alerts || [];

  // Calculate statistics from actual data
  const totalEvents = metadata.total_events || events.length || 0;
  const totalProcesses = processTree.processes?.length || 0;
  const totalAlerts = alerts.length || 0;
  const highSeverityAlerts = alerts.filter(alert => alert.severity === 'critical' || alert.severity === 'high').length || 0;
  const eventCounts = aggregations.event_counts || {};
  const topProcesses = aggregations.top_processes || [];
  const activeProcesses = processTree.processes?.filter(p => !p.exit_time).length || 0;

  const tabs = [
    { id: 'overview', name: 'Overview', icon: ChartBarIcon },
    { id: 'metadata', name: 'Metadata', icon: Cog6ToothIcon },
    { id: 'events', name: 'Events', icon: DocumentTextIcon },
    { id: 'process-tree', name: 'Process Tree', icon: CpuChipIcon },
    { id: 'aggregations', name: 'Aggregations', icon: ChartBarIcon },
    { id: 'alerts', name: 'Alerts', icon: ExclamationTriangleIcon },
    { id: 'timeline', name: 'Timeline', icon: ClockIcon },
  ];

  const renderOverview = () => (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <DocumentTextIcon className="h-6 w-6 text-blue-500" aria-hidden="true" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Total Events
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {totalEvents.toLocaleString()}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CpuChipIcon className="h-6 w-6 text-green-500" aria-hidden="true" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Active Processes
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {activeProcesses}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-500" aria-hidden="true" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Critical Alerts
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {highSeverityAlerts}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ClockIcon className="h-6 w-6 text-purple-500" aria-hidden="true" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Collection Duration
                  </dt>
                  <dd className="text-lg font-medium text-gray-900 dark:text-white">
                    {metadata.collection_start && metadata.collection_end ? 
                      `${Math.round((new Date(metadata.collection_end) - new Date(metadata.collection_start)) / (1000 * 60))} min` :
                      'Ongoing'
                    }
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Event Type Distribution */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ChartBarIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Event Type Breakdown</h3>
          </div>
          <div className="space-y-4">
            {Object.entries(eventCounts).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className={`h-3 w-3 rounded-full mr-3 ${
                    type === 'process' ? 'bg-blue-500' :
                    type === 'file' ? 'bg-green-500' :
                    type === 'registry' ? 'bg-yellow-500' :
                    type === 'network' ? 'bg-purple-500' : 'bg-gray-500'
                  }`}></div>
                  <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                    {type.replace(/_/g, ' ')} Events
                  </span>
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  {count.toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <PlayIcon className="h-6 w-6 text-green-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Top Active Processes</h3>
          </div>
          <div className="space-y-3">
            {topProcesses.slice(0, 5).map((process, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center">
                  <CpuChipIcon className="h-5 w-5 text-blue-500 mr-2" />
                  <div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {process.process_name}
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400">
                      PID: {process.pid}
                    </div>
                  </div>
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  {process.event_count?.toLocaleString() || 0} events
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Insights */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center mb-4">
          <ShieldExclamationIcon className="h-6 w-6 text-orange-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Analysis Summary</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {Object.keys(metadata.event_types || {}).length}
            </div>
            <div className="text-sm text-blue-700 dark:text-blue-300">Event Types Monitored</div>
          </div>
          <div className="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {totalProcesses}
            </div>
            <div className="text-sm text-green-700 dark:text-green-300">Processes Tracked</div>
          </div>
          <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {totalAlerts}
            </div>
            <div className="text-sm text-orange-700 dark:text-orange-300">Total Alerts</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return renderOverview();
      case 'metadata':
        return <ProcmonMetadata procmonData={procmonData} />;
      case 'events':
        return <EventAnalysis procmonData={procmonData} />;
      case 'process-tree':
        return <ProcessTreeVisualization procmonData={procmonData} />;
      case 'aggregations':
        return <AggregationSummary procmonData={procmonData} />;
      case 'alerts':
        return <AlertDashboard procmonData={procmonData} />;
      case 'timeline':
        return <ProcmonTimeline procmonData={procmonData} />;
      default:
        return renderOverview();
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Process Monitor Analysis</h1>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
            Comprehensive process monitoring and behavioral analysis based on ProcMon data
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-8 overflow-x-auto" aria-label="Tabs">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                      : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                  } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
                >
                  <Icon className="h-5 w-5" />
                  <span>{tab.name}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Tab Content */}
        {renderContent()}
      </div>
    </Layout>
  );
};

export default ProcessMonitor;
