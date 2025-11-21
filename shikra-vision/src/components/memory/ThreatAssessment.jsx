import React, { useMemo } from 'react';
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  FlagIcon,
  GlobeAltIcon,
  HashtagIcon,
  ClockIcon
} from '@heroicons/react/24/outline';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

const ThreatAssessment = ({ memoryData }) => {
  const threatAssessment = memoryData?.threat_assessment || {};
  const iocs = threatAssessment.iocs || [];
  const mitreTactics = threatAssessment.mitre_tactics || [];
  const timeline = threatAssessment.timeline || [];

  // Risk score visualization
  const riskScore = threatAssessment.overall_risk_score || 0;
  const confidence = threatAssessment.confidence || 0;

  // IOC distribution
  const iocData = useMemo(() => {
    const types = {};
    iocs.forEach(ioc => {
      types[ioc.type] = (types[ioc.type] || 0) + 1;
    });
    
    const colors = {
      'hash': '#DC2626',
      'ip': '#EA580C', 
      'domain': '#D97706',
      'url': '#65A30D',
      'registry': '#059669',
      'file': '#0891B2',
      'email': '#7C3AED',
      'mutex': '#BE185D'
    };

    return Object.entries(types).map(([type, count]) => ({
      name: type.toUpperCase(),
      value: count,
      color: colors[type] || '#6B7280'
    }));
  }, [iocs]);

  // MITRE ATT&CK tactics distribution
  const tacticData = useMemo(() => {
    const tactics = {};
    mitreTactics.forEach(tactic => {
      const tacticName = tactic.technique.split(' ')[0]; // Get first word
      tactics[tacticName] = (tactics[tacticName] || 0) + 1;
    });

    return Object.entries(tactics).map(([name, count]) => ({
      name,
      count,
      techniques: mitreTactics.filter(t => t.technique.startsWith(name)).length
    }));
  }, [mitreTactics]);

  const getRiskColor = (score) => {
    if (score >= 8) return 'text-red-600 dark:text-red-400';
    if (score >= 6) return 'text-orange-600 dark:text-orange-400';
    if (score >= 4) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-green-600 dark:text-green-400';
  };

  const getRiskBg = (score) => {
    if (score >= 8) return 'bg-red-100 dark:bg-red-900';
    if (score >= 6) return 'bg-orange-100 dark:bg-orange-900';
    if (score >= 4) return 'bg-yellow-100 dark:bg-yellow-900';
    return 'bg-green-100 dark:bg-green-900';
  };

  const getSeverityBadge = (severity) => {
    const badges = {
      'critical': { color: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200', icon: ExclamationTriangleIcon },
      'high': { color: 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200', icon: ExclamationTriangleIcon },
      'medium': { color: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200', icon: FlagIcon },
      'low': { color: 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200', icon: FlagIcon }
    };
    return badges[severity] || badges.low;
  };

  const getIocTypeIcon = (type) => {
    const icons = {
      'hash': HashtagIcon,
      'ip': GlobeAltIcon,
      'domain': GlobeAltIcon,
      'url': GlobeAltIcon,
      'registry': FlagIcon,
      'file': ExclamationTriangleIcon,
      'email': GlobeAltIcon,
      'mutex': ShieldExclamationIcon
    };
    return icons[type] || FlagIcon;
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
      {/* Overall Risk Assessment */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className={`p-6 rounded-lg border ${getRiskBg(riskScore)} border-gray-200 dark:border-gray-700`}>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Overall Risk Score</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">System threat level assessment</p>
            </div>
            <div className="text-right">
              <div className={`text-4xl font-bold ${getRiskColor(riskScore)}`}>
                {riskScore.toFixed(1)}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">/ 10.0</div>
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
              <div 
                className={`h-3 rounded-full ${
                  riskScore >= 8 ? 'bg-red-500' :
                  riskScore >= 6 ? 'bg-orange-500' :
                  riskScore >= 4 ? 'bg-yellow-500' :
                  'bg-green-500'
                }`}
                style={{ width: `${(riskScore / 10) * 100}%` }}
              />
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Confidence Level</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">Analysis confidence score</p>
            </div>
            <div className="text-right">
              <div className="text-4xl font-bold text-blue-600 dark:text-blue-400">
                {(confidence * 100).toFixed(0)}%
              </div>
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
              <div 
                className="h-3 rounded-full bg-blue-500"
                style={{ width: `${confidence * 100}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Threat Categories */}
      {threatAssessment.threat_categories && threatAssessment.threat_categories.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Threat Categories</h3>
          <div className="flex flex-wrap gap-2">
            {threatAssessment.threat_categories.map((category, index) => (
              <span key={index} className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                <ExclamationTriangleIcon className="h-4 w-4 mr-1" />
                {category.replace('_', ' ').toUpperCase()}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Charts Row */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* IOC Distribution */}
        {iocData.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">IOC Distribution</h3>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={iocData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {iocData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* MITRE ATT&CK Tactics */}
        {tacticData.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">MITRE ATT&CK Tactics</h3>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={tacticData}>
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
                  <Bar dataKey="count" fill="#DC2626" name="Occurrences" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>

      {/* IOC List */}
      {iocs.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <FlagIcon className="h-6 w-6 text-red-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Indicators of Compromise (IOCs)</h3>
          </div>
          <div className="space-y-3">
            {iocs.map((ioc, index) => {
              const IconComponent = getIocTypeIcon(ioc.type);
              return (
                <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <IconComponent className="h-5 w-5 text-red-500 mt-0.5 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-xs font-medium px-2 py-1 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded">
                        {ioc.type.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                      {ioc.value}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      {ioc.context}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Techniques */}
      {mitreTactics.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ShieldExclamationIcon className="h-6 w-6 text-orange-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Techniques</h3>
          </div>
          <div className="space-y-3">
            {mitreTactics.map((tactic, index) => (
              <div key={index} className="flex items-start space-x-3 p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-800">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <span className="text-sm font-medium text-orange-800 dark:text-orange-200">
                      {tactic.tactic}
                    </span>
                    <span className="text-xs px-2 py-1 bg-orange-200 dark:bg-orange-800 text-orange-800 dark:text-orange-200 rounded">
                      MITRE ATT&CK
                    </span>
                  </div>
                  <p className="text-sm text-gray-900 dark:text-white font-medium mb-1">
                    {tactic.technique}
                  </p>
                  {tactic.evidence && tactic.evidence.length > 0 && (
                    <div className="text-xs text-gray-600 dark:text-gray-300">
                      <span className="font-medium">Evidence:</span> {tactic.evidence.join(', ')}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      {timeline.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ClockIcon className="h-6 w-6 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Threat Timeline</h3>
          </div>
          <div className="flow-root">
            <ul role="list" className="-mb-8">
              {timeline.map((event, eventIdx) => {
                const severityBadge = getSeverityBadge(event.severity);
                const IconComponent = severityBadge.icon;
                
                return (
                  <li key={eventIdx}>
                    <div className="relative pb-8">
                      {eventIdx !== timeline.length - 1 ? (
                        <span className="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200 dark:bg-gray-600" aria-hidden="true" />
                      ) : null}
                      <div className="relative flex space-x-3">
                        <div>
                          <span className={`h-8 w-8 rounded-full flex items-center justify-center ring-8 ring-white dark:ring-gray-800 ${
                            event.severity === 'critical' ? 'bg-red-500' :
                            event.severity === 'high' ? 'bg-orange-500' :
                            event.severity === 'medium' ? 'bg-yellow-500' :
                            'bg-blue-500'
                          }`}>
                            <IconComponent className="h-5 w-5 text-white" />
                          </span>
                        </div>
                        <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                          <div>
                            <p className="text-sm text-gray-900 dark:text-white font-medium">
                              {event.event}
                            </p>
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${severityBadge.color}`}>
                              {event.severity}
                            </span>
                          </div>
                          <div className="text-right text-sm whitespace-nowrap text-gray-500 dark:text-gray-400">
                            <time dateTime={event.timestamp}>
                              {new Date(event.timestamp).toLocaleString()}
                            </time>
                          </div>
                        </div>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatAssessment;
