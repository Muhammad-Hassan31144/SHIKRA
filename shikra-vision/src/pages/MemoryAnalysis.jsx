import React, { useState } from 'react';
import { 
  CpuChipIcon,
  ExclamationTriangleIcon,
  DocumentTextIcon,
  ShieldExclamationIcon,
  BugAntIcon,
  FolderIcon,
  ClockIcon,
  LightBulbIcon
} from '@heroicons/react/24/outline';
import useCyberStore from '../store/cyberStore';
import MemoryMetadata from '../components/memory/MemoryMetadata';
import ProcessAnalysis from '../components/memory/ProcessAnalysis';
import MalwareAnalysis from '../components/memory/MalwareAnalysis';
import RegistryAnalysis from '../components/memory/RegistryAnalysis';
import FileArtifacts from '../components/memory/FileArtifacts';
import ThreatAssessment from '../components/memory/ThreatAssessment';
import MemoryRecommendations from '../components/memory/MemoryRecommendations';

const MemoryAnalysis = () => {
  const { threatData } = useCyberStore();
  const memoryData = threatData?.memory;
  const [activeTab, setActiveTab] = useState('overview');

  // Calculate statistics from actual memory data
  const stats = {
    totalProcesses: memoryData?.analysis_results?.processes?.length || 0,
    suspiciousProcesses: memoryData?.analysis_results?.processes?.filter(p => 
      p.anomalies && p.anomalies.length > 0
    ).length || 0,
    malfindHits: memoryData?.analysis_results?.malware_analysis?.malfind_results?.length || 0,
    riskScore: memoryData?.threat_assessment?.overall_risk_score || 0
  };

  const tabs = [
    { id: 'overview', name: 'Overview', icon: CpuChipIcon },
    { id: 'processes', name: 'Processes', icon: DocumentTextIcon },
    { id: 'malware', name: 'Malware Analysis', icon: BugAntIcon },
    { id: 'registry', name: 'Registry', icon: FolderIcon },
    { id: 'files', name: 'File Artifacts', icon: DocumentTextIcon },
    { id: 'threats', name: 'Threat Assessment', icon: ShieldExclamationIcon },
    { id: 'timeline', name: 'Timeline', icon: ClockIcon },
    { id: 'recommendations', name: 'Recommendations', icon: LightBulbIcon }
  ];

  if (!memoryData) {
    return (
      <div className="p-6">
        <div className="text-center py-12">
          <CpuChipIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No Memory Data</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Memory analysis data will appear here when available.
          </p>
        </div>
      </div>
    );
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <MemoryMetadata memoryData={memoryData} />;
      case 'processes':
        return <ProcessAnalysis memoryData={memoryData} />;
      case 'malware':
        return <MalwareAnalysis memoryData={memoryData} />;
      case 'registry':
        return <RegistryAnalysis memoryData={memoryData} />;
      case 'files':
        return <FileArtifacts memoryData={memoryData} />;
      case 'threats':
        return <ThreatAssessment memoryData={memoryData} />;
      case 'timeline':
        return (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center mb-4">
              <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Memory Analysis Timeline</h3>
            </div>
            {memoryData.threat_assessment?.timeline ? (
              <ThreatAssessment memoryData={memoryData} />
            ) : (
              <div className="text-center py-8">
                <ClockIcon className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">No timeline data available</p>
              </div>
            )}
          </div>
        );
      case 'recommendations':
        return <MemoryRecommendations memoryData={memoryData} />;
      default:
        return <MemoryMetadata memoryData={memoryData} />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Memory Analysis</h1>
        <p className="mt-1 text-gray-600 dark:text-gray-400">
          Volatility 3 memory forensics analysis results
        </p>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Processes</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.totalProcesses}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Suspicious</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.suspiciousProcesses}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <BugAntIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Malfind Hits</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.malfindHits}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ShieldExclamationIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Risk Score</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.riskScore.toFixed(1)}/10</p>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="flex space-x-8 px-6" aria-label="Tabs">
            {tabs.map((tab) => {
              const IconComponent = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                  } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
                >
                  <IconComponent className="h-5 w-5" />
                  <span>{tab.name}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6">
          {renderTabContent()}
        </div>
      </div>
    </div>
  );
};

export default MemoryAnalysis;
