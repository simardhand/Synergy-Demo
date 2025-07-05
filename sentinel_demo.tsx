import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, Area, AreaChart } from 'recharts';
import { Shield, AlertTriangle, Search, Activity, Users, Globe, FileText, Settings, Play, Database, TrendingUp, Eye, Zap, Clock, CheckCircle, XCircle, AlertCircle, Target, Wifi, Lock } from 'lucide-react';

const SentinelDemo = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedQuery, setSelectedQuery] = useState(null);
  const [isRunningQuery, setIsRunningQuery] = useState(false);
  const [queryResults, setQueryResults] = useState([]);
  const [liveAttack, setLiveAttack] = useState(null);
  const [attackPhase, setAttackPhase] = useState(0);
  const [isAttackActive, setIsAttackActive] = useState(false);
  const [detectionLog, setDetectionLog] = useState([]);
  const [mitigationActions, setMitigationActions] = useState([]);
  const [attackTimeline, setAttackTimeline] = useState([]);

  // Attack scenario phases
  const attackScenario = [
    {
      phase: 'Initial Access',
      description: 'Phishing email with malicious attachment detected',
      indicator: 'suspicious_email.zip executed on WS-DEV-001',
      severity: 'Medium',
      duration: 3000,
      iocs: ['email-attachment-hash-abc123', 'sender-ip-203.0.113.45'],
      mitre: 'T1566.001 - Spearphishing Attachment'
    },
    {
      phase: 'Execution',
      description: 'PowerShell process spawned with encoded command',
      indicator: 'powershell.exe -enc [base64] detected',
      severity: 'High',
      duration: 2000,
      iocs: ['powershell-command-hash-def456', 'process-id-1234'],
      mitre: 'T1059.001 - PowerShell'
    },
    {
      phase: 'Persistence',
      description: 'Registry modification for persistence mechanism',
      indicator: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified',
      severity: 'High',
      duration: 2500,
      iocs: ['registry-key-modified', 'backdoor.exe'],
      mitre: 'T1547.001 - Registry Run Keys'
    },
    {
      phase: 'Discovery',
      description: 'Network reconnaissance activity detected',
      indicator: 'Port scanning and service enumeration observed',
      severity: 'Medium',
      duration: 4000,
      iocs: ['scan-pattern-192.168.1.0/24', 'nmap-signature'],
      mitre: 'T1046 - Network Service Scanning'
    },
    {
      phase: 'Lateral Movement',
      description: 'Attempted RDP connection to domain controller',
      indicator: 'Multiple failed RDP attempts to DC-01',
      severity: 'Critical',
      duration: 3000,
      iocs: ['failed-rdp-attempts', 'dc-01-target'],
      mitre: 'T1021.001 - Remote Desktop Protocol'
    },
    {
      phase: 'Collection',
      description: 'Data staging and compression detected',
      indicator: 'Large archive created in temp directory',
      severity: 'High',
      duration: 2000,
      iocs: ['data-archive-temp.7z', 'compression-activity'],
      mitre: 'T1560.001 - Archive via Utility'
    },
    {
      phase: 'Exfiltration',
      description: 'Suspicious outbound network traffic',
      indicator: 'Large data transfer to external IP',
      severity: 'Critical',
      duration: 3000,
      iocs: ['external-ip-185.199.108.153', 'data-transfer-500MB'],
      mitre: 'T1041 - Exfiltration Over C2 Channel'
    }
  ];

  const [realTimeData, setRealTimeData] = useState({
    events: 1247,
    alerts: 23,
    incidents: 5,
    threatLevel: 'Medium'
  });

  const huntingQueries = [
    {
      id: 1,
      name: 'PowerShell Malware Detection',
      category: 'Execution',
      description: 'Detects encoded PowerShell commands and suspicious execution patterns',
      severity: 'High',
      query: `SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine contains "-enc" or CommandLine contains "IEX"
| project TimeGenerated, Computer, Account, CommandLine, ProcessId`,
      results: []
    },
    {
      id: 2,
      name: 'Lateral Movement Detection',
      category: 'Lateral Movement',
      description: 'Identifies suspicious RDP and SMB connection patterns',
      severity: 'Critical',
      query: `SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4624, 4625, 4648)
| where LogonType in (3, 10)
| summarize FailedAttempts = countif(EventID == 4625), 
            SuccessfulAttempts = countif(EventID == 4624)
            by Account, IpAddress, TargetComputerName
| where FailedAttempts > 3`,
      results: []
    },
    {
      id: 3,
      name: 'Data Exfiltration Detection',
      category: 'Exfiltration',
      description: 'Monitors for large outbound data transfers and suspicious network patterns',
      severity: 'Critical',
      query: `CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceAction == "allow"
| where SentBytes > 100000000
| project TimeGenerated, SourceIP, DestinationIP, SentBytes, Protocol`,
      results: []
    }
  ];

  const mitigationPlaybook = {
    'PowerShell': [
      { action: 'Block suspicious PowerShell execution', status: 'pending', duration: 1000 },
      { action: 'Isolate affected endpoint WS-DEV-001', status: 'pending', duration: 2000 },
      { action: 'Update PowerShell execution policy', status: 'pending', duration: 1500 }
    ],
    'Lateral Movement': [
      { action: 'Block RDP access from source IP', status: 'pending', duration: 1000 },
      { action: 'Reset compromised account credentials', status: 'pending', duration: 2500 },
      { action: 'Enable additional MFA requirements', status: 'pending', duration: 1500 }
    ],
    'Exfiltration': [
      { action: 'Block external IP communication', status: 'pending', duration: 1000 },
      { action: 'Quarantine suspicious files', status: 'pending', duration: 1500 },
      { action: 'Notify data protection team', status: 'pending', duration: 500 }
    ]
  };

  useEffect(() => {
    let interval;
    
    if (isAttackActive && attackPhase < attackScenario.length) {
      const currentPhase = attackScenario[attackPhase];
      
      interval = setInterval(() => {
        // Add to timeline
        setAttackTimeline(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          phase: currentPhase.phase,
          description: currentPhase.description,
          severity: currentPhase.severity,
          mitre: currentPhase.mitre
        }]);

        // Add to detection log
        setDetectionLog(prev => [...prev, {
          timestamp: new Date().toLocaleTimeString(),
          rule: `${currentPhase.phase} Detection Rule`,
          indicator: currentPhase.indicator,
          severity: currentPhase.severity,
          confidence: Math.floor(Math.random() * 30) + 70 + '%',
          iocs: currentPhase.iocs
        }]);

        // Update real-time metrics
        setRealTimeData(prev => ({
          events: prev.events + Math.floor(Math.random() * 50) + 10,
          alerts: prev.alerts + 1,
          incidents: currentPhase.severity === 'Critical' ? prev.incidents + 1 : prev.incidents,
          threatLevel: currentPhase.severity === 'Critical' ? 'Critical' : 
                     currentPhase.severity === 'High' ? 'High' : prev.threatLevel
        }));

        setAttackPhase(prev => prev + 1);
      }, currentPhase.duration);
    } else if (attackPhase >= attackScenario.length && isAttackActive) {
      // Attack complete, start mitigation
      setIsAttackActive(false);
      startMitigation();
    }

    return () => clearInterval(interval);
  }, [isAttackActive, attackPhase]);

  const startAttackSimulation = () => {
    setIsAttackActive(true);
    setAttackPhase(0);
    setDetectionLog([]);
    setMitigationActions([]);
    setAttackTimeline([]);
    setRealTimeData({
      events: 1247,
      alerts: 23,
      incidents: 5,
      threatLevel: 'Medium'
    });
  };

  const startMitigation = () => {
    const allActions = Object.values(mitigationPlaybook).flat();
    let actionIndex = 0;

    const executeAction = () => {
      if (actionIndex < allActions.length) {
        const action = allActions[actionIndex];
        
        setMitigationActions(prev => [...prev, {
          ...action,
          timestamp: new Date().toLocaleTimeString(),
          status: 'executing'
        }]);

        setTimeout(() => {
          setMitigationActions(prev => 
            prev.map((a, i) => 
              i === actionIndex ? { ...a, status: 'completed' } : a
            )
          );
          
          actionIndex++;
          if (actionIndex < allActions.length) {
            setTimeout(executeAction, 1000);
          } else {
            // All mitigations complete
            setTimeout(() => {
              setRealTimeData(prev => ({
                ...prev,
                threatLevel: 'Low',
                incidents: Math.max(0, prev.incidents - 3)
              }));
            }, 2000);
          }
        }, action.duration);
      }
    };

    setTimeout(executeAction, 2000);
  };

  const stopSimulation = () => {
    setIsAttackActive(false);
    setAttackPhase(0);
  };

  const getSeverityColor = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100 border-red-200';
      case 'high': return 'text-red-500 bg-red-50 border-red-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-100 border-green-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getThreatLevelColor = (level) => {
    switch(level?.toLowerCase()) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-blue-900 text-white p-4 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8" />
            <div>
              <h1 className="text-2xl font-bold">Microsoft Sentinel</h1>
              <p className="text-blue-200">Live Threat Detection & Response Demo</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className={`flex items-center space-x-2 px-3 py-1 rounded-lg ${getThreatLevelColor(realTimeData.threatLevel)}`}>
              <Activity className="h-4 w-4" />
              <span className="text-sm">Threat Level: {realTimeData.threatLevel}</span>
            </div>
            <div className="text-sm">
              <div>Workspace: ThreatHunting-Demo</div>
              <div className="text-blue-200">Last Updated: {new Date().toLocaleString()}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Simulation Controls */}
      <div className="bg-gray-800 text-white p-4 border-b">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold">🎯 Live Attack Simulation</h2>
            {isAttackActive && (
              <div className="flex items-center space-x-2 text-red-400">
                <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                <span>Attack in Progress - Phase {attackPhase + 1}/7</span>
              </div>
            )}
          </div>
          <div className="flex space-x-3">
            <button
              onClick={startAttackSimulation}
              disabled={isAttackActive}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
            >
              {isAttackActive ? 'Attack Running...' : '🚨 Start APT Attack'}
            </button>
            <button
              onClick={stopSimulation}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg font-medium transition-colors"
            >
              🛑 Reset Demo
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white border-b border-gray-200">
        <div className="flex space-x-8 px-6">
          {[
            { id: 'dashboard', label: 'Live Dashboard', icon: TrendingUp },
            { id: 'attack-timeline', label: 'Attack Timeline', icon: Clock },
            { id: 'detection', label: 'Detection Rules', icon: Eye },
            { id: 'response', label: 'Response Actions', icon: Shield },
            { id: 'hunting', label: 'Threat Hunting', icon: Search }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-4 px-2 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="p-6">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Real-time Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Security Events</p>
                    <p className="text-3xl font-bold text-gray-900">{realTimeData.events.toLocaleString()}</p>
                  </div>
                  <Activity className={`h-8 w-8 ${isAttackActive ? 'text-red-500 animate-pulse' : 'text-blue-500'}`} />
                </div>
                <p className={`text-xs mt-2 ${isAttackActive ? 'text-red-600' : 'text-green-600'}`}>
                  {isAttackActive ? '↑ Attack detected' : '→ Normal activity'}
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Active Alerts</p>
                    <p className="text-3xl font-bold text-gray-900">{realTimeData.alerts}</p>
                  </div>
                  <AlertTriangle className={`h-8 w-8 ${realTimeData.alerts > 25 ? 'text-red-500' : 'text-yellow-500'}`} />
                </div>
                <p className={`text-xs mt-2 ${isAttackActive ? 'text-red-600' : 'text-blue-600'}`}>
                  {isAttackActive ? '↑ Increasing' : '→ Stable'}
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Open Incidents</p>
                    <p className="text-3xl font-bold text-gray-900">{realTimeData.incidents}</p>
                  </div>
                  <Target className={`h-8 w-8 ${realTimeData.incidents > 7 ? 'text-red-500' : 'text-green-500'}`} />
                </div>
                <p className={`text-xs mt-2 ${realTimeData.incidents > 7 ? 'text-red-600' : 'text-green-600'}`}>
                  {realTimeData.incidents > 7 ? '↑ Critical incidents' : '→ Under control'}
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Mitigation Status</p>
                    <p className="text-lg font-bold text-gray-900">
                      {mitigationActions.filter(a => a.status === 'completed').length}/
                      {mitigationActions.length || 'Ready'}
                    </p>
                  </div>
                  <CheckCircle className={`h-8 w-8 ${
                    mitigationActions.length > 0 && mitigationActions.every(a => a.status === 'completed') 
                      ? 'text-green-500' 
                      : mitigationActions.some(a => a.status === 'executing')
                      ? 'text-blue-500 animate-spin'
                      : 'text-gray-400'
                  }`} />
                </div>
                <p className="text-xs text-gray-600 mt-2">
                  {mitigationActions.some(a => a.status === 'executing') ? 'Auto-remediation active' : 'Standing by'}
                </p>
              </div>
            </div>

            {/* Live Detection Feed */}
            {detectionLog.length > 0 && (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="p-6 border-b bg-gray-50">
                  <h3 className="text-lg font-semibold flex items-center">
                    <Eye className="h-5 w-5 mr-2 text-blue-600" />
                    Live Detection Feed
                    <div className="ml-3 w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                  </h3>
                </div>
                <div className="max-h-96 overflow-y-auto">
                  {detectionLog.slice().reverse().map((log, index) => (
                    <div key={index} className="p-4 border-b hover:bg-gray-50 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3">
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(log.severity)}`}>
                              {log.severity}
                            </span>
                            <span className="text-sm font-medium text-gray-900">{log.rule}</span>
                            <span className="text-xs text-gray-500">{log.timestamp}</span>
                          </div>
                          <p className="text-sm text-gray-700 mt-1">{log.indicator}</p>
                          <div className="flex items-center space-x-4 mt-2">
                            <span className="text-xs text-blue-600">Confidence: {log.confidence}</span>
                            <span className="text-xs text-gray-500">IOCs: {log.iocs.length}</span>
                          </div>
                        </div>
                        <AlertCircle className={`h-5 w-5 ${
                          log.severity === 'Critical' ? 'text-red-500' :
                          log.severity === 'High' ? 'text-red-400' :
                          log.severity === 'Medium' ? 'text-yellow-500' : 'text-green-500'
                        }`} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'attack-timeline' && (
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold flex items-center">
                <Clock className="h-5 w-5 mr-2 text-blue-600" />
                Attack Kill Chain Timeline
              </h3>
              <p className="text-sm text-gray-600 mt-1">MITRE ATT&CK framework mapped attack progression</p>
            </div>
            <div className="p-6">
              {attackTimeline.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Start the attack simulation to see the kill chain progression</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {attackTimeline.map((event, index) => (
                    <div key={index} className="flex items-start space-x-4">
                      <div className="flex-shrink-0">
                        <div className={`w-4 h-4 rounded-full ${
                          event.severity === 'Critical' ? 'bg-red-500' :
                          event.severity === 'High' ? 'bg-red-400' :
                          event.severity === 'Medium' ? 'bg-yellow-500' : 'bg-blue-500'
                        }`}></div>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-3">
                          <h4 className="text-sm font-semibold text-gray-900">{event.phase}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded ${getSeverityColor(event.severity)}`}>
                            {event.severity}
                          </span>
                          <span className="text-xs text-gray-500">{event.time}</span>
                        </div>
                        <p className="text-sm text-gray-700 mt-1">{event.description}</p>
                        <p className="text-xs text-blue-600 mt-1 font-mono">{event.mitre}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'detection' && (
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold flex items-center">
                <Eye className="h-5 w-5 mr-2 text-blue-600" />
                Detection Rules & Analytics
              </h3>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[
                  { 
                    name: 'PowerShell Execution Monitor',
                    status: 'active',
                    triggered: detectionLog.filter(l => l.rule.includes('Execution')).length,
                    description: 'Monitors for encoded PowerShell and suspicious execution patterns'
                  },
                  { 
                    name: 'Lateral Movement Detector',
                    status: 'active',
                    triggered: detectionLog.filter(l => l.rule.includes('Lateral')).length,
                    description: 'Detects suspicious RDP and SMB connection attempts'
                  },
                  { 
                    name: 'Data Exfiltration Monitor',
                    status: 'active',
                    triggered: detectionLog.filter(l => l.rule.includes('Collection')).length,
                    description: 'Identifies large data transfers and staging activities'
                  },
                  { 
                    name: 'Persistence Mechanism Detector',
                    status: 'active',
                    triggered: detectionLog.filter(l => l.rule.includes('Persistence')).length,
                    description: 'Monitors registry modifications and startup persistence'
                  },
                  { 
                    name: 'Network Reconnaissance Monitor',
                    status: 'active',
                    triggered: detectionLog.filter(l => l.rule.includes('Discovery')).length,
                    description: 'Detects port scanning and service enumeration'
                  },
                  { 
                    name: 'Initial Access Detector',
                    status: 'active',
                    triggered: detectionLog.filter(l => l.rule.includes('Initial')).length,
                    description: 'Identifies phishing and malicious file execution'
                  }
                ].map((rule, index) => (
                  <div key={index} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-semibold text-gray-900">{rule.name}</h4>
                      <div className="flex items-center space-x-2">
                        <div className={`w-3 h-3 rounded-full ${rule.status === 'active' ? 'bg-green-500' : 'bg-gray-400'}`}></div>
                        {rule.triggered > 0 && (
                          <span className="bg-red-100 text-red-800 px-2 py-1 text-xs font-semibold rounded-full">
                            {rule.triggered}
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">{rule.description}</p>
                    <div className="text-xs text-gray-500">
                      <div>Status: {rule.status === 'active' ? 'Active' : 'Inactive'}</div>
                      <div>Triggered: {rule.triggered} times today</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'response' && (
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold flex items-center">
                <Shield className="h-5 w-5 mr-2 text-blue-600" />
                Automated Response Actions
              </h3>
              <p className="text-sm text-gray-600 mt-1">SOAR playbooks and automated mitigation responses</p>
            </div>
            <div className="p-6">
              {mitigationActions.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Response actions will appear here when threats are detected</p>
                  <p className="text-sm mt-2">Start the attack simulation to see automated responses</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {mitigationActions.map((action, index) => (
                    <div key={index} className="flex items-center space-x-4 p-4 border rounded-lg hover:bg-gray-50 transition-colors">
                      <div className="flex-shrink-0">
                        {action.status === 'completed' ? (
                          <CheckCircle className="h-6 w-6 text-green-500" />
                        ) : action.status === 'executing' ? (
                          <div className="h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                        ) : (
                          <Clock className="h-6 w-6 text-gray-400" />
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-3">
                          <h4 className="text-sm font-semibold text-gray-900">{action.action}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                            action.status === 'completed' ? 'bg-green-100 text-green-800' :
                            action.status === 'executing' ? 'bg-blue-100 text-blue-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {action.status === 'completed' ? 'Completed' :
                             action.status === 'executing' ? 'Executing' : 'Pending'}
                          </span>
                          <span className="text-xs text-gray-500">{action.timestamp}</span>
                        </div>
                        <p className="text-xs text-gray-600 mt-1">Automated SOAR response triggered</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'hunting' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b">
                <h3 className="text-lg font-semibold">Threat Hunting Queries</h3>
                <p className="text-sm text-gray-600 mt-1">Pre-built KQL queries for proactive threat detection</p>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6">
                {/* Query List */}
                <div className="space-y-4">
                  {huntingQueries.map((query) => (
                    <div key={query.id} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <h4 className="font-semibold text-gray-900">{query.name}</h4>
                          <p className="text-sm text-gray-600 mt-1">{query.description}</p>
                          <div className="flex items-center space-x-4 mt-2">
                            <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">{query.category}</span>
                            <span className={`text-xs px-2 py-1 rounded ${getSeverityColor(query.severity)}`}>
                              {query.severity}
                            </span>
                          </div>
                        </div>
                        <button
                          onClick={() => {
                            setSelectedQuery(query);
                            setIsRunningQuery(true);
                            setTimeout(() => {
                              setIsRunningQuery(false);
                              if (query.id === 1) {
                                setQueryResults([
                                  { computer: 'WS-DEV-001', account: 'user1', command: 'powershell.exe -enc [encoded]', risk: 'Critical' },
                                  { computer: 'SRV-001', account: 'admin', command: 'powershell.exe IEX downloadstring', risk: 'High' }
                                ]);
                              } else if (query.id === 2) {
                                setQueryResults([
                                  { account: 'admin', ipAddress: '192.168.1.100', targetComputer: 'DC-01', failedAttempts: 5, risk: 'Critical' },
                                  { account: 'service', ipAddress: '10.0.0.15', targetComputer: 'SRV-002', failedAttempts: 8, risk: 'High' }
                                ]);
                              } else {
                                setQueryResults([
                                  { sourceIP: '192.168.1.105', destIP: '185.199.108.153', sentBytes: '500MB', protocol: 'HTTPS', risk: 'Critical' },
                                  { sourceIP: '10.0.0.22', destIP: '203.0.113.45', sentBytes: '250MB', protocol: 'TCP', risk: 'Medium' }
                                ]);
                              }
                            }, 2000);
                          }}
                          disabled={isRunningQuery}
                          className="ml-4 inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                        >
                          <Play className="h-4 w-4 mr-1" />
                          {isRunningQuery && selectedQuery?.id === query.id ? 'Running...' : 'Run'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Query Results */}
                <div className="bg-gray-50 rounded-lg p-4">
                  {selectedQuery ? (
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-3">Query: {selectedQuery.name}</h4>
                      
                      {/* KQL Query Display */}
                      <div className="bg-gray-900 text-green-400 p-4 rounded-lg mb-4 font-mono text-sm overflow-x-auto">
                        <pre>{selectedQuery.query}</pre>
                      </div>

                      {isRunningQuery ? (
                        <div className="flex items-center justify-center py-8">
                          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                          <span className="ml-2 text-gray-600">Executing query...</span>
                        </div>
                      ) : queryResults.length > 0 ? (
                        <div>
                          <h5 className="font-medium text-gray-900 mb-2">Results ({queryResults.length} records)</h5>
                          <div className="bg-white rounded border overflow-hidden">
                            <table className="min-w-full divide-y divide-gray-200">
                              <thead className="bg-gray-50">
                                <tr>
                                  {Object.keys(queryResults[0]).map((key) => (
                                    <th key={key} className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                      {key.replace(/([A-Z])/g, ' $1').trim()}
                                    </th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody className="bg-white divide-y divide-gray-200">
                                {queryResults.map((result, index) => (
                                  <tr key={index} className="hover:bg-gray-50">
                                    {Object.entries(result).map(([key, value]) => (
                                      <td key={key} className="px-4 py-2 whitespace-nowrap text-sm text-gray-900">
                                        {key === 'risk' ? (
                                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                                            value === 'Critical' ? 'bg-red-600 text-white' :
                                            value === 'High' ? 'bg-red-500 text-white' :
                                            value === 'Medium' ? 'bg-yellow-500 text-white' : 'bg-green-500 text-white'
                                          }`}>
                                            {value}
                                          </span>
                                        ) : key === 'command' ? (
                                          <span className="truncate max-w-xs block font-mono text-xs" title={value}>{value}</span>
                                        ) : (
                                          value
                                        )}
                                      </td>
                                    ))}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      ) : (
                        <div className="text-center py-8 text-gray-500">
                          Click "Run" to execute the query and see results
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>Select a hunting query to view details and run analysis</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Live Attack Status Banner */}
      {isAttackActive && (
        <div className="fixed bottom-4 right-4 max-w-md">
          <div className="bg-red-600 text-white p-4 rounded-lg shadow-lg border-l-4 border-red-800">
            <div className="flex items-start">
              <AlertTriangle className="h-6 w-6 mr-3 mt-0.5 animate-pulse" />
              <div className="flex-1">
                <h4 className="font-semibold">🚨 Active Cyber Attack Detected!</h4>
                <p className="text-sm mt-1">
                  Phase {attackPhase + 1}/7: {attackScenario[attackPhase]?.phase || 'Initializing...'}
                </p>
                <div className="mt-2 bg-red-700 rounded-full h-2">
                  <div 
                    className="bg-white h-2 rounded-full transition-all duration-500"
                    style={{ width: `${((attackPhase + 1) / attackScenario.length) * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mitigation Success Banner */}
      {mitigationActions.length > 0 && mitigationActions.every(a => a.status === 'completed') && (
        <div className="fixed bottom-4 left-4 max-w-md">
          <div className="bg-green-600 text-white p-4 rounded-lg shadow-lg border-l-4 border-green-800">
            <div className="flex items-start">
              <CheckCircle className="h-6 w-6 mr-3 mt-0.5" />
              <div className="flex-1">
                <h4 className="font-semibold">✅ Threat Neutralized!</h4>
                <p className="text-sm mt-1">
                  All automated response actions completed successfully.
                </p>
                <p className="text-xs mt-1 opacity-90">
                  {mitigationActions.length} mitigation steps executed
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SentinelDemo;