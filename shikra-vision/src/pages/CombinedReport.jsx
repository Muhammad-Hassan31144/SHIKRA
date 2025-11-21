import React, { useState } from 'react';
import useCyberStore  from '../store/cyberStore';
import {
  ClipboardDocumentListIcon,
  ChartBarIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  GlobeAltIcon,
  DocumentTextIcon,
  EyeIcon
} from '@heroicons/react/24/outline';

// Import combined analysis components
import CombinedMetadata from '../components/combined/CombinedMetadata';
import CorrelationAnalysis from '../components/combined/CorrelationAnalysis';
import IOCAnalysis from '../components/combined/IOCAnalysis';
import TimelineAnalysis from '../components/combined/TimelineAnalysis';
import MITRETechniques from '../components/combined/MITRETechniques';
import ThreatLandscape from '../components/combined/ThreatLandscape';
import AttackTimeline from '../components/combined/AttackTimeline';
import EvidenceSummary from '../components/combined/EvidenceSummary';

const CombinedReport = () => {
  const { threatData } = useCyberStore();
  const [activeTab, setActiveTab] = useState('overview');

  // Get combined analysis data from store
  const combinedData = threatData?.combinedAnalysis || {};

  const tabs = [
    {
      id: 'overview',
      name: 'Overview',
      icon: ClipboardDocumentListIcon,
      component: CombinedMetadata
    },
    {
      id: 'correlations',
      name: 'Correlations',
      icon: ChartBarIcon,
      component: CorrelationAnalysis
    },
    {
      id: 'iocs',
      name: 'IOCs',
      icon: ExclamationTriangleIcon,
      component: IOCAnalysis
    },
    {
      id: 'timeline',
      name: 'Timeline',
      icon: ClockIcon,
      component: TimelineAnalysis
    },
    {
      id: 'mitre',
      name: 'MITRE ATT&CK',
      icon: ShieldExclamationIcon,
      component: MITRETechniques
    },
    {
      id: 'threats',
      name: 'Threat Landscape',
      icon: GlobeAltIcon,
      component: ThreatLandscape
    },
    {
      id: 'attack-timeline',
      name: 'Attack Timeline',
      icon: ClockIcon,
      component: AttackTimeline
    },
    {
      id: 'evidence',
      name: 'Evidence',
      icon: DocumentTextIcon,
      component: EvidenceSummary
    }
  ];

  const activeTabData = tabs.find(tab => tab.id === activeTab);
  const ActiveComponent = activeTabData?.component;

  // Generate summary statistics
  const getSummaryStats = () => {
    const summary = combinedData?.summary || {};
    
    return {
      totalIOCs: Object.values(summary.iocs || {}).reduce((sum, iocs) => sum + (Array.isArray(iocs) ? iocs.length : 0), 0),
      timelineEvents: summary.timeline?.events?.length || 0,
      mitreTechniques: summary.mitre_techniques?.length || 0,
      correlations: Object.values(combinedData?.analysis?.correlations || {}).reduce((sum, corrs) => sum + (Array.isArray(corrs) ? corrs.length : 0), 0)
    };
  };

  const stats = getSummaryStats();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="px-6 py-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Combined Cybersecurity Analysis Report
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mt-2">
                Comprehensive analysis combining ProcMon, Memory Forensics, and Network Traffic data
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <button className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                <DocumentTextIcon className="h-5 w-5 mr-2" />
                Export Report
              </button>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mt-6">
            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
              <div className="flex items-center">
                <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
                <div className="ml-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total IOCs</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.totalIOCs}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
              <div className="flex items-center">
                <ClockIcon className="h-8 w-8 text-blue-500" />
                <div className="ml-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Timeline Events</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.timelineEvents}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
              <div className="flex items-center">
                <ShieldExclamationIcon className="h-8 w-8 text-purple-500" />
                <div className="ml-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">MITRE Techniques</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.mitreTechniques}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
              <div className="flex items-center">
                <ChartBarIcon className="h-8 w-8 text-green-500" />
                <div className="ml-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Correlations</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.correlations}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="px-6">
          <nav className="flex space-x-8" aria-label="Tabs">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              const Icon = tab.icon;
              
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    isActive
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                      : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                  }`}
                >
                  <Icon className="h-5 w-5 mr-2" />
                  {tab.name}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      <div className="px-6 py-8">
        {ActiveComponent ? (
          <ActiveComponent combinedData={combinedData} />
        ) : (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8">
            <div className="text-center">
              <EyeIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                Tab content not available
              </h3>
              <p className="text-gray-500 dark:text-gray-400">
                The selected tab component could not be loaded.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* No Data State */}
      {(!combinedData || Object.keys(combinedData).length === 0) && (
        <div className="px-6 py-8">
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12">
            <div className="text-center">
              <ClipboardDocumentListIcon className="h-16 w-16 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <h3 className="text-xl font-medium text-gray-900 dark:text-white mb-2">
                No Combined Analysis Data Available
              </h3>
              <p className="text-gray-500 dark:text-gray-400 mb-6">
                Combined analysis data has not been loaded yet. Please ensure that individual analysis 
                data (ProcMon, Memory, Network) has been processed and correlations have been generated.
              </p>
              <div className="space-y-2 text-sm text-gray-500 dark:text-gray-400">
                <p>• Process monitoring data from ProcMon analysis</p>
                <p>• Memory artifacts from Volatility analysis</p>
                <p>• Network traffic from PCAP analysis</p>
                <p>• Cross-source correlation analysis</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CombinedReport;
