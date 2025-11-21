import React from 'react';
import { 
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  LineChart,
  Line
} from 'recharts';
import { 
  GlobeAltIcon,
  ExclamationTriangleIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

const DNSAnalysis = ({ dnsAnalysis }) => {
  if (!dnsAnalysis || dnsAnalysis.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="text-center py-8">
          <GlobeAltIcon className="mx-auto h-8 w-8 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No DNS analysis data</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            DNS analysis data will appear here when available.
          </p>
        </div>
      </div>
    );
  }

  // Calculate DNS statistics
  const getDNSStats = () => {
    const stats = {
      total_queries: dnsAnalysis.length,
      malicious_domains: 0,
      suspicious_domains: 0,
      clean_domains: 0,
      avg_response_time: 0,
      query_types: {},
      response_codes: {}
    };

    let totalResponseTime = 0;
    let responseTimeCount = 0;

    dnsAnalysis.forEach(query => {
      // Count reputation
      const reputation = query.threat_intel?.domain_reputation;
      if (reputation === 'malicious') stats.malicious_domains++;
      else if (reputation === 'suspicious') stats.suspicious_domains++;
      else if (reputation === 'clean') stats.clean_domains++;

      // Calculate average response time
      if (query.response_time) {
        totalResponseTime += query.response_time;
        responseTimeCount++;
      }

      // Count query types
      const queryType = query.query_type || 'Unknown';
      stats.query_types[queryType] = (stats.query_types[queryType] || 0) + 1;

      // Count response codes
      const responseCode = query.response_code || 'Unknown';
      stats.response_codes[responseCode] = (stats.response_codes[responseCode] || 0) + 1;
    });

    stats.avg_response_time = responseTimeCount > 0 ? totalResponseTime / responseTimeCount : 0;

    return stats;
  };

  // Get response time data for chart
  const getResponseTimeData = () => {
    return dnsAnalysis
      .filter(query => query.response_time && query.timestamp)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
      .map((query, index) => ({
        index: index + 1,
        responseTime: query.response_time * 1000, // Convert to milliseconds
        domain: query.query_name,
        reputation: query.threat_intel?.domain_reputation || 'unknown'
      }));
  };

  // Get query type distribution
  const getQueryTypeData = () => {
    const stats = getDNSStats();
    return Object.entries(stats.query_types).map(([type, count]) => ({
      name: type,
      count
    }));
  };

  // Get malicious domains list
  const getMaliciousDomains = () => {
    return dnsAnalysis
      .filter(query => query.threat_intel?.domain_reputation === 'malicious')
      .slice(0, 10)
      .map(query => ({
        domain: query.query_name,
        ip: query.responses?.[0]?.data,
        categories: query.threat_intel?.categories || [],
        dga_probability: query.threat_intel?.dga_probability,
        entropy: query.threat_intel?.entropy,
        first_seen: query.threat_intel?.first_seen
      }));
  };

  const stats = getDNSStats();
  const responseTimeData = getResponseTimeData();
  const queryTypeData = getQueryTypeData();
  const maliciousDomains = getMaliciousDomains();

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className='p-3 rounded-lg shadow-lg border 
            dark:bg-gray-800 dark:border-gray-600 dark:text-white
            bg-white border-gray-200 text-gray-900'
        >
          <p className="font-medium">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }} className="text-sm">
              {entry.name}: {entry.value}
              {entry.dataKey === 'responseTime' && 'ms'}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-6">
      {/* DNS Overview Stats */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="flex items-center mb-4">
          <GlobeAltIcon className="h-6 w-6 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">DNS Analysis Overview</h3>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total_queries}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Total Queries</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">{stats.malicious_domains}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Malicious</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-600">{stats.suspicious_domains}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Suspicious</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">{stats.clean_domains}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Clean</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{(stats.avg_response_time * 1000).toFixed(1)}ms</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Avg Response</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Query Type Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Query Type Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={queryTypeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                <XAxis dataKey="name" stroke="#6B7280" fontSize={12} />
                <YAxis stroke="#6B7280" fontSize={12} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Response Time Trend */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Response Time Trend</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={responseTimeData.slice(0, 50)}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                <XAxis dataKey="index" stroke="#6B7280" fontSize={12} />
                <YAxis stroke="#6B7280" fontSize={12} />
                <Tooltip 
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className='p-3 rounded-lg shadow-lg border 
                            dark:bg-gray-800 dark:border-gray-600 dark:text-white
                            bg-white border-gray-200 text-gray-900'
                        >
                          <p className="font-medium">{data.domain}</p>
                          <p className="text-sm">Response Time: {data.responseTime}ms</p>
                          <p className="text-sm">Reputation: {data.reputation}</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="responseTime" 
                  stroke="#3B82F6" 
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Malicious Domains Table */}
      {maliciousDomains.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center mb-4">
            <ExclamationTriangleIcon className="h-6 w-6 text-red-500 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Malicious Domains Detected</h3>
          </div>
          
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Domain
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Resolved IP
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Categories
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    DGA Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    First Seen
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {maliciousDomains.map((domain, index) => (
                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {domain.domain}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900 dark:text-white">
                        {domain.ip || 'N/A'}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex flex-wrap gap-1">
                        {domain.categories.slice(0, 3).map((category, idx) => (
                          <span key={idx} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                            {category}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900 dark:text-white">
                        {domain.dga_probability ? (domain.dga_probability * 100).toFixed(1) + '%' : 'N/A'}
                      </div>
                      {domain.entropy && (
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          Entropy: {domain.entropy.toFixed(2)}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center text-sm text-gray-900 dark:text-white">
                        <ClockIcon className="h-4 w-4 mr-1 text-gray-400" />
                        {domain.first_seen ? new Date(domain.first_seen).toLocaleDateString() : 'Unknown'}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default DNSAnalysis;
