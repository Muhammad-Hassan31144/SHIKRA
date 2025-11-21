import React from 'react';
import { 
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';
import { 
  EyeIcon,
  ArrowPathIcon,
  DocumentArrowDownIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

const ThreatHunting = ({ threatHunting }) => {
  if (!threatHunting) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="text-center py-8">
          <EyeIcon className="mx-auto h-8 w-8 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No threat hunting data</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Threat hunting analysis will appear here when available.
          </p>
        </div>
      </div>
    );
  }

  // Prepare beaconing data for visualization
  const getBeaconingChartData = () => {
    if (!threatHunting.beaconing_analysis) return [];
    
    return threatHunting.beaconing_analysis.map((beacon, index) => ({
      index: index + 1,
      score: beacon.beacon_score * 100,
      interval: beacon.interval_consistency * 100,
      size: beacon.size_consistency * 100,
      avgInterval: beacon.average_interval,
      jitter: beacon.jitter,
      src_ip: beacon.src_ip,
      dst_ip: beacon.dst_ip
    }));
  };

  // Prepare radar chart data for threat analysis
  const getThreatRadarData = () => {
    const data = [];
    
    if (threatHunting.beaconing_analysis && threatHunting.beaconing_analysis.length > 0) {
      const avgScore = threatHunting.beaconing_analysis.reduce((sum, b) => sum + b.beacon_score, 0) / threatHunting.beaconing_analysis.length;
      data.push({ category: 'Beaconing', score: avgScore * 100 });
    }
    
    if (threatHunting.lateral_movement && threatHunting.lateral_movement.length > 0) {
      const movement = threatHunting.lateral_movement[0];
      const successRate = movement.successful_connections / movement.authentication_attempts;
      data.push({ category: 'Lateral Movement', score: successRate * 100 });
    }
    
    if (threatHunting.data_exfiltration && threatHunting.data_exfiltration.length > 0) {
      const exfil = threatHunting.data_exfiltration[0];
      const riskScore = exfil.total_bytes > 10000000 ? 80 : exfil.total_bytes > 1000000 ? 60 : 40;
      data.push({ category: 'Data Exfiltration', score: riskScore });
    }
    
    return data;
  };

  const beaconingData = getBeaconingChartData();
  const radarData = getThreatRadarData();

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
              {entry.name}: {typeof entry.value === 'number' ? entry.value.toFixed(2) : entry.value}
              {entry.dataKey?.includes('score') || entry.dataKey?.includes('consistency') ? '%' : ''}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  const formatBytes = (bytes) => {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      {/* Threat Hunting Overview */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="flex items-center mb-4">
          <EyeIcon className="h-6 w-6 text-purple-500 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Threat Hunting Analysis</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
            <ArrowPathIcon className="h-8 w-8 text-purple-500 mx-auto mb-2" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {threatHunting.beaconing_analysis?.length || 0}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Beaconing Sessions</div>
          </div>
          
          <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
            <DocumentArrowDownIcon className="h-8 w-8 text-orange-500 mx-auto mb-2" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {threatHunting.lateral_movement?.length || 0}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Lateral Movement</div>
          </div>
          
          <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
            <DocumentArrowDownIcon className="h-8 w-8 text-red-500 mx-auto mb-2" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {threatHunting.data_exfiltration?.length || 0}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Data Exfiltration</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Beaconing Analysis Chart */}
        {beaconingData.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Beaconing Score Analysis</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={beaconingData}>
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
                            <p className="font-medium">{data.src_ip} → {data.dst_ip}</p>
                            <p className="text-sm">Beacon Score: {data.score.toFixed(1)}%</p>
                            <p className="text-sm">Interval Consistency: {data.interval.toFixed(1)}%</p>
                            <p className="text-sm">Size Consistency: {data.size.toFixed(1)}%</p>
                            <p className="text-sm">Avg Interval: {data.avgInterval}s</p>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Line type="monotone" dataKey="score" stroke="#8B5CF6" strokeWidth={2} name="Beacon Score" />
                  <Line type="monotone" dataKey="interval" stroke="#06B6D4" strokeWidth={2} name="Interval Consistency" />
                  <Line type="monotone" dataKey="size" stroke="#10B981" strokeWidth={2} name="Size Consistency" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Threat Analysis Radar */}
        {radarData.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Threat Analysis Overview</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart data={radarData}>
                  <PolarGrid stroke="#E5E7EB" />
                  <PolarAngleAxis dataKey="category" tick={{ fontSize: 12, fill: '#6B7280' }} />
                  <PolarRadiusAxis 
                    domain={[0, 100]} 
                    tick={{ fontSize: 10, fill: '#6B7280' }}
                    tickFormatter={(value) => `${value}%`}
                  />
                  <Radar
                    name="Threat Score"
                    dataKey="score"
                    stroke="#DC2626"
                    fill="#DC2626"
                    fillOpacity={0.3}
                    strokeWidth={2}
                  />
                  <Tooltip content={<CustomTooltip />} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>

      {/* Detailed Analysis Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Beaconing Details */}
        {threatHunting.beaconing_analysis && threatHunting.beaconing_analysis.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Beaconing Analysis Details</h3>
            <div className="space-y-3">
              {threatHunting.beaconing_analysis.map((beacon, index) => (
                <div key={index} className="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {beacon.src_ip} → {beacon.dst_ip}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {beacon.total_beacons} beacons over {((new Date(beacon.last_beacon) - new Date(beacon.first_beacon)) / 1000 / 60).toFixed(0)} minutes
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                        beacon.beacon_score > 0.8 ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200' :
                        beacon.beacon_score > 0.6 ? 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200' :
                        'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200'
                      }`}>
                        {(beacon.beacon_score * 100).toFixed(0)}% score
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {beacon.average_interval}s interval
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Lateral Movement */}
        {threatHunting.lateral_movement && threatHunting.lateral_movement.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Lateral Movement Detection</h3>
            <div className="space-y-3">
              {threatHunting.lateral_movement.map((movement, index) => (
                <div key={index} className="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        Source: {movement.src_ip}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        Targets: {movement.targets?.join(', ')}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        Protocols: {movement.protocols?.join(', ')}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {movement.successful_connections}/{movement.authentication_attempts}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        Success Rate: {((movement.successful_connections / movement.authentication_attempts) * 100).toFixed(0)}%
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Data Exfiltration */}
      {threatHunting.data_exfiltration && threatHunting.data_exfiltration.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Data Exfiltration Analysis</h3>
          <div className="space-y-4">
            {threatHunting.data_exfiltration.map((exfil, index) => (
              <div key={index} className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div>
                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">Internal Source</div>
                    <div className="text-sm font-mono text-gray-900 dark:text-white">{exfil.src_internal}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">External Destination</div>
                    <div className="text-sm font-mono text-gray-900 dark:text-white">{exfil.dst_external}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Data</div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">{formatBytes(exfil.total_bytes)}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">File Types</div>
                    <div className="text-sm text-gray-900 dark:text-white">{exfil.file_types?.join(', ')}</div>
                  </div>
                </div>
                <div className="mt-3 flex items-center space-x-4 text-xs">
                  <span className={`inline-flex items-center px-2 py-1 rounded ${
                    exfil.encryption_detected ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' : 
                    'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                  }`}>
                    Encryption: {exfil.encryption_detected ? 'Yes' : 'No'}
                  </span>
                  <span className={`inline-flex items-center px-2 py-1 rounded ${
                    exfil.compression_detected ? 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200' : 
                    'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200'
                  }`}>
                    Compression: {exfil.compression_detected ? 'Yes' : 'No'}
                  </span>
                  <span className="text-gray-500 dark:text-gray-400">
                    Protocols: {exfil.protocols?.join(', ')}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatHunting;
