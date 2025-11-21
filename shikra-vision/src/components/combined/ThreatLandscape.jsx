import React, { useState } from 'react';
import {
  GlobeAltIcon,
  MapIcon,
  UserGroupIcon,
  BugAntIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  ShieldExclamationIcon,
  ServerIcon,
  LockClosedIcon,
  DocumentTextIcon,
  EyeIcon,
  FunnelIcon
} from '@heroicons/react/24/outline';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';

const ThreatLandscape = ({ combinedData }) => {
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedGeography, setSelectedGeography] = useState('all');
  
  const analysis = combinedData?.analysis || {};
  const threatLandscape = analysis.threat_landscape || {};

  // Extract data from threat landscape
  const threats = threatLandscape.threats || [];
  const geolocation = threatLandscape.geolocation || {};
  const threatActors = threatLandscape.threat_actors || [];
  const malwareFamilies = threatLandscape.malware_families || [];
  const attackVectors = threatLandscape.attack_vectors || [];

  // Filter threats
  const getFilteredThreats = () => {
    let filtered = threats;
    
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(threat => threat.category === selectedCategory);
    }
    
    if (selectedGeography !== 'all') {
      filtered = filtered.filter(threat => 
        threat.origin_country === selectedGeography
      );
    }
    
    return filtered;
  };

  const filteredThreats = getFilteredThreats();

  // Prepare chart data
  const prepareThreatCategoryData = () => {
    const categories = threats.reduce((acc, threat) => {
      const category = threat.category || 'Unknown';
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {});
    
    return Object.entries(categories).map(([name, value]) => ({ name, value }));
  };

  const prepareSeverityData = () => {
    const severities = threats.reduce((acc, threat) => {
      const severity = threat.severity || 'unknown';
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {});
    
    return Object.entries(severities).map(([name, value]) => ({ name, value }));
  };

  const prepareGeographyData = () => {
    const countries = threats.reduce((acc, threat) => {
      const country = threat.origin_country || 'Unknown';
      acc[country] = (acc[country] || 0) + 1;
      return acc;
    }, {});
    
    return Object.entries(countries)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  };

  const prepareAttackVectorData = () => {
    return attackVectors.map(vector => ({
      vector: vector.name,
      prevalence: vector.prevalence || 0,
      effectiveness: vector.effectiveness || 0,
      detection_difficulty: vector.detection_difficulty || 0
    }));
  };

  const categoryData = prepareThreatCategoryData();
  const severityData = prepareSeverityData();
  const geographyData = prepareGeographyData();
  const attackVectorData = prepareAttackVectorData();

  // Color schemes
  const COLORS = ['#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6', '#F97316', '#06B6D4', '#84CC16'];
  
  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#EF4444',
      high: '#F97316',
      medium: '#F59E0B',
      low: '#3B82F6',
      info: '#6B7280'
    };
    return colors[severity] || colors.info;
  };

  const getCategoryIcon = (category) => {
    const icons = {
      malware: BugAntIcon,
      phishing: ExclamationTriangleIcon,
      ransomware: LockClosedIcon,
      apt: UserGroupIcon,
      botnet: ServerIcon,
      trojan: ShieldExclamationIcon,
      backdoor: DocumentTextIcon
    };
    return icons[category.toLowerCase()] || BugAntIcon;
  };

  const formatThreatName = (name) => {
    return name.split('_').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  // Get unique categories and countries for filters
  const uniqueCategories = [...new Set(threats.map(t => t.category))].filter(Boolean);
  const uniqueCountries = [...new Set(threats.map(t => t.origin_country))].filter(Boolean);

  return (
    <div className="space-y-6">
      {/* Threat Landscape Overview */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Active Threats</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {threats.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <UserGroupIcon className="h-8 w-8 text-orange-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Threat Actors</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {threatActors.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <BugAntIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Malware Families</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {malwareFamilies.length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center">
            <MapIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">Countries</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {uniqueCountries.length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Threat Categories Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Threat Categories</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={categoryData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {categoryData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar 
                  dataKey="value" 
                  fill={(entry) => getSeverityColor(entry.name)}
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Geographic Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top Origin Countries</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={geographyData} layout="horizontal">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" width={80} />
                <Tooltip />
                <Bar dataKey="value" fill="#3B82F6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Vector Analysis */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Attack Vector Analysis</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={attackVectorData}>
                <PolarGrid />
                <PolarAngleAxis dataKey="vector" />
                <PolarRadiusAxis angle={90} domain={[0, 100]} />
                <Radar
                  name="Prevalence"
                  dataKey="prevalence"
                  stroke="#3B82F6"
                  fill="#3B82F6"
                  fillOpacity={0.3}
                />
                <Radar
                  name="Effectiveness"
                  dataKey="effectiveness"
                  stroke="#EF4444"
                  fill="#EF4444"
                  fillOpacity={0.3}
                />
                <Tooltip />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex flex-col space-y-4 lg:flex-row lg:items-center lg:justify-between lg:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <FunnelIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Category:</span>
            </div>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Categories</option>
              {uniqueCategories.map(category => (
                <option key={category} value={category}>{formatThreatName(category)}</option>
              ))}
            </select>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <MapIcon className="h-5 w-5 text-gray-500 mr-2" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Geography:</span>
            </div>
            <select
              value={selectedGeography}
              onChange={(e) => setSelectedGeography(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Countries</option>
              {uniqueCountries.map(country => (
                <option key={country} value={country}>{country}</option>
              ))}
            </select>
            
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredThreats.length} threats
            </span>
          </div>
        </div>
      </div>

      {/* Threat Details */}
      <div className="space-y-6">
        {/* Threat Actors */}
        {threatActors.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Identified Threat Actors</h3>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {threatActors.map((actor, index) => (
                  <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">{actor.name}</h4>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {actor.confidence}% confidence
                      </span>
                    </div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Type:</span>
                        <span className="text-gray-900 dark:text-white">{actor.type}</span>
                      </div>
                      {actor.origin && (
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Origin:</span>
                          <span className="text-gray-900 dark:text-white">{actor.origin}</span>
                        </div>
                      )}
                      {actor.motivation && (
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Motivation:</span>
                          <span className="text-gray-900 dark:text-white">{actor.motivation}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Malware Families */}
        {malwareFamilies.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Malware Families</h3>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {malwareFamilies.map((malware, index) => (
                  <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">{malware.name}</h4>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        malware.severity === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200' :
                        malware.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200' :
                        'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200'
                      }`}>
                        {malware.severity}
                      </span>
                    </div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600 dark:text-gray-400">Type:</span>
                        <span className="text-gray-900 dark:text-white">{malware.type}</span>
                      </div>
                      {malware.platform && (
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Platform:</span>
                          <span className="text-gray-900 dark:text-white">{malware.platform}</span>
                        </div>
                      )}
                      {malware.first_seen && (
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">First Seen:</span>
                          <span className="text-gray-900 dark:text-white">
                            {new Date(malware.first_seen).toLocaleDateString()}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Active Threats List */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Active Threats</h3>
          </div>
          <div className="p-6">
            {filteredThreats.length > 0 ? (
              <div className="space-y-4">
                {filteredThreats.map((threat, index) => {
                  const CategoryIcon = getCategoryIcon(threat.category || '');
                  
                  return (
                    <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-700">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          <CategoryIcon className="h-6 w-6 text-gray-500" />
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                              {threat.name || 'Unknown Threat'}
                            </h4>
                            <p className="text-sm text-gray-600 dark:text-gray-400">
                              {threat.description || 'No description available'}
                            </p>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            threat.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200' :
                            threat.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-200' :
                            threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200' :
                            'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200'
                          }`}>
                            {threat.severity || 'unknown'}
                          </span>
                          {threat.origin_country && (
                            <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                              {threat.origin_country}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-12">
                <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
                <p className="text-gray-500 dark:text-gray-400">
                  No threats found matching your criteria
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatLandscape;
