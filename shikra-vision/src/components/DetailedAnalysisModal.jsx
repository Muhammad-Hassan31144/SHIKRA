import React, { useState, useMemo, useCallback } from 'react';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from './ui/index.jsx';
import {
  ChevronRightIcon,
  MagnifyingGlassIcon,
  DocumentTextIcon,
  ChartBarIcon,
  ClockIcon,
  CpuChipIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  FunnelIcon,
  ArrowsUpDownIcon,
  EyeIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';

// Advanced drill-down modal for detailed item analysis
const DetailedAnalysisModal = ({ 
  isOpen, 
  onClose, 
  item, 
  itemType, 
  relatedData = [],
}) => {
  const [activeTab, setActiveTab] = useState('overview');

  if (!item) return null;

  const getRelatedItems = (item, allData) => {
    switch (itemType) {
      case 'process':
        return {
          files: allData.filter(d => d.process_info?.pid === item.pid && d.event_type === 'file'),
          network: allData.filter(d => d.process_info?.pid === item.pid && d.event_type === 'network'),
          registry: allData.filter(d => d.process_info?.pid === item.pid && d.event_type === 'registry'),
          children: allData.filter(d => d.process_info?.ppid === item.pid),
          timeline: allData.filter(d => d.process_info?.pid === item.pid).sort((a, b) => 
            new Date(a.timestamp) - new Date(b.timestamp)
          )
        };
      case 'network':
        return {
          connections: allData.filter(d => d.target_path?.includes(item.target_path?.split(':')[0])),
          processes: allData.filter(d => d.target_path === item.target_path),
          geoLocation: item.geoip || {},
          threatIntel: item.enrichment?.threat_intel || {}
        };
      case 'file':
        return {
          processes: allData.filter(d => d.target_path === item.target_path),
          operations: allData.filter(d => d.target_path === item.target_path),
          hashAnalysis: item.file_info || {},
          signatures: item.enrichment?.file_info || {}
        };
      default:
        return {};
    }
  };

  const related = getRelatedItems(item, relatedData);

  const ThreatIndicator = ({ score, severity }) => (
    <div className="flex items-center space-x-2">
      <div className={`h-3 w-3 rounded-full ${
        severity === 'critical' ? 'bg-red-500' :
        severity === 'high' ? 'bg-orange-500' :
        severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
      }`} />
      <span className="text-sm font-medium">
        {severity?.toUpperCase()} ({score ? Math.round(score * 100) : 0}%)
      </span>
    </div>
  );

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className='max-w-6xl max-h-[90vh] overflow-y-auto dark:bg-gray-900 dark:text-white bg-white text-gray-900'>
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div>
              <DialogTitle className="text-2xl font-bold">
                {itemType === 'process' ? item.process_info?.name || 'Unknown Process' :
                 itemType === 'network' ? `Network: ${item.target_path}` :
                 itemType === 'file' ? `File: ${item.target_path?.split('\\').pop()}` :
                 'Detailed Analysis'}
              </DialogTitle>
              <DialogDescription>
                {itemType === 'process' ? `PID: ${item.process_info?.pid} | PPID: ${item.process_info?.ppid}` :
                 itemType === 'network' ? `${item.operation} | ${new Date(item.timestamp).toLocaleString()}` :
                 itemType === 'file' ? `${item.operation} | ${new Date(item.timestamp).toLocaleString()}` :
                 'Comprehensive analysis of the selected item'}
              </DialogDescription>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="relationships">Relationships</TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Basic Information */}
              <Card>
                <CardHeader>
                  <CardTitle>Basic Information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {itemType === 'process' && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Process Name:</span>
                        <span className="font-mono">{item.process_info?.name}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">PID:</span>
                        <span className="font-mono">{item.process_info?.pid}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Parent PID:</span>
                        <span className="font-mono">{item.process_info?.ppid}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">User:</span>
                        <span className="font-mono">{item.process_info?.user || 'Unknown'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Path:</span>
                        <span className="font-mono text-xs break-all">{item.process_info?.path}</span>
                      </div>
                    </>
                  )}
                  
                  {itemType === 'network' && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Operation:</span>
                        <span className="font-mono">{item.operation}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Target:</span>
                        <span className="font-mono">{item.target_path}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Result:</span>
                        <Badge variant={item.result === 'success' ? 'success' : 'destructive'}>
                          {item.result}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Timestamp:</span>
                        <span className="font-mono text-sm">{new Date(item.timestamp).toLocaleString()}</span>
                      </div>
                    </>
                  )}

                  {itemType === 'file' && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Operation:</span>
                        <span className="font-mono">{item.operation}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">File Path:</span>
                        <span className="font-mono text-xs break-all">{item.target_path}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Result:</span>
                        <Badge variant={item.result === 'success' ? 'success' : 'destructive'}>
                          {item.result}
                        </Badge>
                      </div>
                      {item.enrichment?.file_info?.md5 && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">MD5:</span>
                          <span className="font-mono text-xs">{item.enrichment.file_info.md5}</span>
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>

              {/* Threat Analysis */}
              <Card>
                <CardHeader>
                  <CardTitle>Threat Analysis</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {item.enrichment?.threat_intel && (
                    <>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-500">Threat Level:</span>
                        <ThreatIndicator 
                          score={item.enrichment.threat_intel.score}
                          severity={item.enrichment.threat_intel.severity}
                        />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Verdict:</span>
                        <Badge variant={
                          item.enrichment.threat_intel.verdict === 'malicious' ? 'destructive' :
                          item.enrichment.threat_intel.verdict === 'suspicious' ? 'warning' : 'success'
                        }>
                          {item.enrichment.threat_intel.verdict}
                        </Badge>
                      </div>
                      {item.enrichment.threat_intel.mitre_tactics && (
                        <div>
                          <span className="text-gray-500 block mb-2">MITRE ATT&CK:</span>
                          <div className="flex flex-wrap gap-1">
                            {item.enrichment.threat_intel.mitre_tactics.map((tactic, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {tactic}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                  
                  {item.enrichment?.file_info && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Digital Signature:</span>
                        <Badge variant={
                          item.enrichment.file_info.digital_signature?.includes('Valid') ? 'success' : 'destructive'
                        }>
                          {item.enrichment.file_info.digital_signature || 'Not Available'}
                        </Badge>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Command Line (for processes) */}
            {itemType === 'process' && item.process_info?.command_line && (
              <Card>
                <CardHeader>
                  <CardTitle>Command Line</CardTitle>
                </CardHeader>
                <CardContent>
                  <code className="block p-4 bg-gray-100 dark:bg-gray-800 rounded text-sm overflow-x-auto">
                    {item.process_info.command_line}
                  </code>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Timeline Tab */}
          <TabsContent value="timeline" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Event Timeline</CardTitle>
                <CardDescription>
                  Chronological view of all related events
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {related.timeline?.map((event, index) => (
                    <div key={index} className="flex items-start space-x-4 p-3 border rounded">
                      <div className="flex-shrink-0 w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">{event.operation}</span>
                          <span className="text-sm text-gray-500">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          {event.event_type} • {event.target_path || 'No target'}
                        </p>
                        {event.enrichment?.threat_intel?.severity && (
                          <Badge 
                            variant={event.enrichment.threat_intel.severity === 'high' ? 'destructive' : 'warning'}
                            className="mt-1"
                          >
                            {event.enrichment.threat_intel.severity}
                          </Badge>
                        )}
                      </div>
                    </div>
                  )) || (
                    <p className="text-gray-500 text-center py-8">No timeline data available</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Relationships Tab */}
          <TabsContent value="relationships" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* File Operations */}
              {related.files && (
                <Card>
                  <CardHeader>
                    <CardTitle>File Operations ({related.files.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {related.files.slice(0, 10).map((file, index) => (
                        <div key={index} className="flex items-center justify-between text-sm p-2 border rounded">
                          <span className="truncate">{file.target_path?.split('\\').pop()}</span>
                          <Badge variant="outline">{file.operation}</Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Network Connections */}
              {related.network && (
                <Card>
                  <CardHeader>
                    <CardTitle>Network Connections ({related.network.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {related.network.slice(0, 10).map((conn, index) => (
                        <div key={index} className="flex items-center justify-between text-sm p-2 border rounded">
                          <span className="truncate font-mono">{conn.target_path}</span>
                          <Badge variant="outline">{conn.operation}</Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Child Processes */}
              {related.children && (
                <Card>
                  <CardHeader>
                    <CardTitle>Child Processes ({related.children.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {related.children.slice(0, 10).map((child, index) => (
                        <div key={index} className="flex items-center justify-between text-sm p-2 border rounded">
                          <span className="truncate">{child.process_info?.name}</span>
                          <span className="font-mono text-xs">PID: {child.process_info?.pid}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Registry Operations */}
              {related.registry && (
                <Card>
                  <CardHeader>
                    <CardTitle>Registry Operations ({related.registry.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {related.registry.slice(0, 10).map((reg, index) => (
                        <div key={index} className="flex items-center justify-between text-sm p-2 border rounded">
                          <span className="truncate">{reg.target_path?.split('\\').pop()}</span>
                          <Badge variant="outline">{reg.operation}</Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Analysis Tab */}
          <TabsContent value="analysis" className="space-y-6">
            <div className="grid grid-cols-1 gap-6">
              {/* Behavioral Analysis */}
              <Card>
                <CardHeader>
                  <CardTitle>Behavioral Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {item.enrichment?.behavioral_analysis ? (
                      <>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Anomaly Score:</span>
                          <span className="font-bold text-lg">
                            {item.enrichment.behavioral_analysis.anomaly_score}/10
                          </span>
                        </div>
                        {item.enrichment.behavioral_analysis.pattern_matches && (
                          <div>
                            <span className="text-gray-500 block mb-2">Pattern Matches:</span>
                            <div className="flex flex-wrap gap-2">
                              {item.enrichment.behavioral_analysis.pattern_matches.map((pattern, index) => (
                                <Badge key={index} variant="outline">
                                  {pattern.replace(/_/g, ' ')}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </>
                    ) : (
                      <p className="text-gray-500 text-center py-8">
                        No behavioral analysis data available
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Additional Context */}
              <Card>
                <CardHeader>
                  <CardTitle>Additional Context</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-500">Event Type:</span>
                      <Badge>{item.event_type}</Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">First Seen:</span>
                      <span className="font-mono text-sm">{new Date(item.timestamp).toLocaleString()}</span>
                    </div>
                    {item.tags && (
                      <div>
                        <span className="text-gray-500 block mb-2">Tags:</span>
                        <div className="flex flex-wrap gap-1">
                          {item.tags.map((tag, index) => (
                            <Badge key={index} variant="secondary" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};

export default DetailedAnalysisModal;
