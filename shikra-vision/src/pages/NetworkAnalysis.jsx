import React, { useState } from 'react';
import useCyberStore from '../store/cyberStore';
import { 
  GlobeAltIcon, 
  ExclamationTriangleIcon,
  ChartBarIcon,
  ShieldExclamationIcon,
  MapPinIcon,
  SignalIcon,
  DocumentTextIcon,
  BugAntIcon,
  EyeIcon,
  ClockIcon,
  FlagIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

// Import network-specific components
import {
  NetworkMetadata,
  ProtocolAnalysis,
  ThreatIntelligence,
  NetworkFlowTable,
  DNSAnalysis,
  ProtocolAnomalies,
  ThreatHunting,
  NetworkTimeline
} from '../components/network';

const NetworkAnalysis = () => {
  const { threatData } = useCyberStore();
  const networkData = threatData?.network;
  
  const [activeTab, setActiveTab] = useState('overview');

  const formatBytes = (bytes) => {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (!networkData) {
    return (
      <div className="p-6">
        <div className="text-center py-12">
          <GlobeAltIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No network data</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Network analysis data will appear here when available.
          </p>
        </div>
      </div>
    );
  }

  // Calculate overview statistics from actual data
  const getOverviewStats = () => {
    const stats = {
      totalFlows: networkData.network_flows?.length || 0,
      maliciousFlows: 0,
      totalTraffic: 0,
      uniqueCountries: new Set(),
      dnsQueries: networkData.dns_analysis?.length || 0,
      httpRequests: networkData.http_analysis?.length || 0,
      anomalies: networkData.protocol_anomalies?.length || 0
    };

    // Calculate from network flows
    if (networkData.network_flows) {
      networkData.network_flows.forEach(flow => {
        if (flow.threat_intel?.dst_reputation === 'malicious') {
          stats.maliciousFlows++;
        }
        
        stats.totalTraffic += (flow.bytes_sent || 0) + (flow.bytes_received || 0);
        
        if (flow.geoip?.dst_geo?.country) {
          stats.uniqueCountries.add(flow.geoip.dst_geo.country);
        }
      });
    }

    stats.uniqueCountries = stats.uniqueCountries.size;
    return stats;
  };

  const overviewStats = getOverviewStats();

  const tabs = [
    { id: 'overview', name: 'Overview', icon: ChartBarIcon },
    { id: 'flows', name: 'Network Flows', icon: GlobeAltIcon },
    { id: 'dns', name: 'DNS Analysis', icon: DocumentTextIcon },
    { id: 'threats', name: 'Threat Intelligence', icon: ShieldExclamationIcon },
    { id: 'anomalies', name: 'Anomalies', icon: BugAntIcon },
    { id: 'hunting', name: 'Threat Hunting', icon: EyeIcon },
    { id: 'timeline', name: 'Timeline & IOCs', icon: ClockIcon }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Network Analysis</h1>
        <p className="mt-1 text-gray-600 dark:text-gray-400">
          Comprehensive analysis of network traffic and threat intelligence based on PCAP data
        </p>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <GlobeAltIcon className="h-6 w-6 text-blue-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Total Flows</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {overviewStats.totalFlows.toLocaleString()}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Malicious</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {overviewStats.maliciousFlows}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <SignalIcon className="h-6 w-6 text-green-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Traffic</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {formatBytes(overviewStats.totalTraffic)}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <MapPinIcon className="h-6 w-6 text-purple-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Countries</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {overviewStats.uniqueCountries}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <DocumentTextIcon className="h-6 w-6 text-cyan-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">DNS Queries</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {overviewStats.dnsQueries}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <GlobeAltIcon className="h-6 w-6 text-indigo-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">HTTP Requests</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {overviewStats.httpRequests}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <BugAntIcon className="h-6 w-6 text-orange-500" />
            <div className="ml-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Anomalies</p>
              <p className="text-lg font-bold text-gray-900 dark:text-white">
                {overviewStats.anomalies}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
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

      {/* Tab Content */}
      <div className="space-y-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <NetworkMetadata metadata={networkData.metadata} />
            <ProtocolAnalysis 
              metadata={networkData.metadata} 
              networkFlows={networkData.network_flows} 
            />
            <ThreatIntelligence 
              networkFlows={networkData.network_flows}
              dnsAnalysis={networkData.dns_analysis}
              httpAnalysis={networkData.http_analysis}
            />
          </div>
        )}

        {activeTab === 'flows' && (
          <NetworkFlowTable networkFlows={networkData.network_flows} />
        )}

        {activeTab === 'dns' && (
          <DNSAnalysis dnsAnalysis={networkData.dns_analysis} />
        )}

        {activeTab === 'threats' && (
          <ThreatIntelligence 
            networkFlows={networkData.network_flows}
            dnsAnalysis={networkData.dns_analysis}
            httpAnalysis={networkData.http_analysis}
          />
        )}

        {activeTab === 'anomalies' && (
          <ProtocolAnomalies protocolAnomalies={networkData.protocol_anomalies} />
        )}

        {activeTab === 'hunting' && (
          <ThreatHunting threatHunting={networkData.threat_hunting} />
        )}

        {activeTab === 'timeline' && (
          <NetworkTimeline 
            timeline={networkData.timeline} 
            iocs={networkData.iocs}
          />
        )}
      </div>
    </div>
  );
};

export default NetworkAnalysis;
