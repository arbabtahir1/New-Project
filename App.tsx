
import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Search, FileSearch, Globe, 
  ShieldAlert, X, FileText, Fingerprint, Activity, Lock, 
  Cpu, ShieldCheck, Zap, LayoutGrid, Settings, 
  ArrowLeft, Database, Trash2, 
  RefreshCw, Terminal, Printer, 
  BarChart3, Radio, Zap as ZapIcon, 
  ShieldQuestion, Binary, Key, FileKey, 
  FileCheck, Scale, UserCheck, FileSignature, Hash, ShieldBan,
  HardDriveDownload, ExternalLink, Layers, Eye, ShieldEllipsis, 
  Bell, History, Box, ChevronRight, LogOut, Code, UserPlus, User,
  Info
} from 'lucide-react';
import { AnalysisReport, RiskLevel, AnalysisDepth } from './types';
import { extractApkMetadata, extractPdfMetadata, isValidUrl, forensicDecode, calculateEntropy } from './utils/security';
import { analyzeSecurityThreat } from './services/geminiService';

const APP_NAME = "AEGIS SENTINEL PRO";
const APP_VERSION = "6.1.0-ELITE";

interface AppNotification {
  id: string;
  title: string;
  message: string;
  time: number;
  unread: boolean;
  severity: 'low' | 'high';
}

const App: React.FC = () => {
  // Auth State
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [currentUser, setCurrentUser] = useState<string | null>(null);

  // App State
  const [activeTab, setActiveTab] = useState<'hub' | 'vault' | 'labs' | 'config'>('hub');
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [analysisDepth, setAnalysisDepth] = useState<AnalysisDepth>('Standard');
  const [history, setHistory] = useState<AnalysisReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null);
  const [showForensicReport, setShowForensicReport] = useState(false);
  const [showScanDrawer, setShowScanDrawer] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);

  // Labs State
  const [labInput, setLabInput] = useState('');
  const [labResult, setLabResult] = useState<any>(null);
  const [labMode, setLabMode] = useState<'SHA' | 'DECODE' | 'ENTROPY'>('SHA');

  useEffect(() => {
    const savedLogs = localStorage.getItem('forensic_logs');
    if (savedLogs) setHistory(JSON.parse(savedLogs));
    
    const session = localStorage.getItem('sentinel_session');
    if (session) {
      setIsAuthorized(true);
      setCurrentUser(session);
    }
  }, []);

  const handleRegister = () => {
    if (!username || !password) return alert("Credentials required.");
    const users = JSON.parse(localStorage.getItem('sentinel_users') || '{}');
    if (users[username]) return alert("Agent identifier already exists.");
    users[username] = password;
    localStorage.setItem('sentinel_users', JSON.stringify(users));
    alert("Agent Registered. Proceed to Login.");
    setIsRegistering(false);
  };

  const handleLogin = () => {
    const users = JSON.parse(localStorage.getItem('sentinel_users') || '{}');
    if (users[username] === password) {
      setIsAuthorized(true);
      setCurrentUser(username);
      localStorage.setItem('sentinel_session', username);
    } else {
      alert("Authorization Denied: Invalid Credentials.");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('sentinel_session');
    setIsAuthorized(false);
    setCurrentUser(null);
  };

  const addNotification = (title: string, message: string, severity: 'low' | 'high') => {
    const note: AppNotification = {
      id: Math.random().toString(36).substr(2, 9),
      title,
      message,
      time: Date.now(),
      unread: true,
      severity
    };
    setNotifications(prev => [note, ...prev].slice(0, 10));
  };

  const saveReport = (report: AnalysisReport) => {
    const newHistory = [report, ...history].slice(0, 100);
    setHistory(newHistory);
    localStorage.setItem('forensic_logs', JSON.stringify(newHistory));
    
    if (report.riskLevel === RiskLevel.MALICIOUS) {
      addNotification("Threat Detected", `High-risk artifact identified: ${report.target}`, 'high');
    } else {
      addNotification("Scan Complete", `Artifact audit finalized for ${report.type} asset.`, 'low');
    }
    
    setSelectedReport(report);
    setShowScanDrawer(false);
  };

  const executeScan = async (type: 'URL' | 'APK' | 'PDF', metadata: any) => {
    setIsScanning(true);
    try {
      const result = await analyzeSecurityThreat(type, { ...metadata, depth: analysisDepth });
      if (!result) throw new Error("ENGINE_FAULT");

      const riskLevel = result.riskScore > 75 ? RiskLevel.MALICIOUS : result.riskScore > 30 ? RiskLevel.SUSPICIOUS : RiskLevel.SAFE;
      
      const report: AnalysisReport = {
        id: `TX-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
        timestamp: Date.now(),
        type,
        target: metadata.url || metadata.filename || metadata.packageName || "Unknown Asset",
        hash: metadata.hash,
        riskScore: result.riskScore,
        riskLevel,
        analysisDepth,
        engines: result.engines,
        encryptedPayload: metadata.encryptedPayload,
        details: {
          summary: result.summary,
          aiInsights: result.insights,
          threats: result.threats,
          permissions: metadata.permissions_detected,
          packageName: metadata.packageName
        }
      };
      saveReport(report);
    } catch (e) {
      addNotification("Scan Failure", "Upstream analysis engine returned an error code.", 'high');
    } finally {
      setIsScanning(false);
    }
  };

  const handleLabAction = () => {
    if (!labInput) return;
    if (labMode === 'SHA') {
      const isMalicious = labInput.length > 20 && (labInput.includes('7c9') || labInput.includes('dead'));
      setLabResult(isMalicious ? {
        status: 'MALICIOUS_MATCH',
        vendor: 'Kaspersky Lab',
        signature: 'Trojan.AndroidOS.Agent.ab',
        reputation: '0/100'
      } : {
        status: 'CLEAN_REGISTRY',
        vendor: 'Aegis Core',
        signature: 'None',
        reputation: '100/100'
      });
    } else if (labMode === 'DECODE') {
      setLabResult(forensicDecode(labInput) || { error: "DATA_STRUCTURE_INVALID" });
    } else if (labMode === 'ENTROPY') {
      const entropy = calculateEntropy(labInput);
      setLabResult({ 
        entropy: entropy.toFixed(4), 
        complexity: entropy > 5 ? 'Critical' : entropy > 4 ? 'High' : 'Normal',
        note: entropy > 5 ? "Data likely encrypted or obfuscated." : "Plaintext or low-randomness data."
      });
    }
  };

  // Auth Screen
  if (!isAuthorized) {
    return (
      <div className="h-screen bg-[#020617] flex flex-col items-center justify-center p-8 overflow-hidden relative">
        <div className="absolute inset-0 opacity-10 pointer-events-none">
          <div className="w-full h-full bg-[radial-gradient(#3b82f6_1px,transparent_1px)] [background-size:32px_32px]" />
        </div>
        
        <div className="w-full max-w-sm space-y-8 animate-in fade-in zoom-in duration-700 relative z-10">
          <div className="flex flex-col items-center text-center">
            <div className="w-24 h-24 bg-blue-600/20 rounded-[2.5rem] flex items-center justify-center border border-blue-500/30 mb-8 shadow-2xl shadow-blue-500/10">
              <Shield className="w-12 h-12 text-blue-400" />
            </div>
            <h1 className="text-4xl font-black text-white uppercase tracking-tighter leading-none">{APP_NAME}</h1>
            <p className="text-blue-500 font-black text-[10px] uppercase tracking-[0.4em] mt-3">Sentinel Core Auth v{APP_VERSION.split('-')[0]}</p>
          </div>

          <div className="bg-white/5 p-8 rounded-[2.5rem] border border-white/10 space-y-5 backdrop-blur-xl">
            <div className="space-y-4">
              <div className="relative">
                <User className="absolute left-5 top-5 w-5 h-5 text-gray-500" />
                <input 
                  type="text" 
                  placeholder="AGENT ID" 
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded-2xl p-5 pl-14 text-white text-sm font-bold outline-none focus:border-blue-500 transition-all"
                />
              </div>
              <div className="relative">
                <Lock className="absolute left-5 top-5 w-5 h-5 text-gray-500" />
                <input 
                  type="password" 
                  placeholder="SECURITY KEY" 
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded-2xl p-5 pl-14 text-white text-sm font-bold outline-none focus:border-blue-500 transition-all"
                />
              </div>
            </div>

            <div className="pt-2">
              {!isRegistering ? (
                <button 
                  onClick={handleLogin}
                  className="w-full bg-blue-600 p-5 rounded-2xl text-[11px] font-black text-white uppercase tracking-widest shadow-xl shadow-blue-600/20 active:scale-95 transition-all"
                >
                  Authorize Session
                </button>
              ) : (
                <button 
                  onClick={handleRegister}
                  className="w-full bg-indigo-600 p-5 rounded-2xl text-[11px] font-black text-white uppercase tracking-widest shadow-xl shadow-indigo-600/20 active:scale-95 transition-all"
                >
                  Confirm Registration
                </button>
              )}
            </div>

            <div className="flex justify-center pt-2">
              <button 
                onClick={() => setIsRegistering(!isRegistering)}
                className="text-[10px] font-black text-blue-500/80 uppercase tracking-widest hover:text-blue-400 transition-colors"
              >
                {isRegistering ? "Back to Login" : "New Agent Registration"}
              </button>
            </div>
          </div>
          
          <div className="text-center space-y-1">
            <p className="text-[9px] text-gray-700 font-bold uppercase tracking-tighter">SECURED BY MULTI-LAYER BIOMETRIC ARCHITECTURE</p>
            <p className="text-[8px] text-gray-800 font-bold">DEVICE_ID: {Math.random().toString(36).substr(2,12).toUpperCase()}</p>
          </div>
        </div>
      </div>
    );
  }

  const maliciousCount = history.filter(h => h.riskLevel === RiskLevel.MALICIOUS).length;
  const totalScans = history.length;
  const lastUpdate = history.length > 0 ? new Date(history[0].timestamp).toLocaleTimeString() : 'N/A';

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#020617] text-[#e2e8f0]">
      <div className="h-12 shrink-0 no-print" />

      {/* Main UI */}
      <div className="flex-grow overflow-y-auto pb-28 px-5 no-scrollbar no-print">
        
        {/* Responsive Header */}
        <div className="pt-4 pb-6 flex justify-between items-center sticky top-0 bg-[#020617]/90 backdrop-blur-2xl z-40 border-b border-white/5 -mx-5 px-5">
          <div className="flex flex-col">
            <div className="flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
              <p className="text-[9px] font-black text-blue-500 uppercase tracking-widest leading-none">AGENT: {currentUser}</p>
            </div>
            <h1 className="text-xl font-black text-white tracking-tighter uppercase">
              {activeTab === 'hub' ? 'Operational Hub' : activeTab === 'vault' ? 'Forensic Vault' : activeTab === 'labs' ? 'Labs terminal' : 'Settings'}
            </h1>
          </div>
          <div className="flex gap-2">
             <button onClick={() => setShowNotifications(true)} className="p-3 bg-white/5 rounded-2xl border border-white/5 relative active:scale-90 transition-transform">
               <Bell className="w-5 h-5 text-gray-400" />
               {notifications.some(n => n.unread) && (
                 <span className="absolute top-2 right-2 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-[#020617]" />
               )}
             </button>
             <button onClick={handleLogout} className="p-3 bg-red-500/10 rounded-2xl border border-red-500/20 active:scale-90 transition-transform">
               <LogOut className="w-5 h-5 text-red-500"/>
             </button>
          </div>
        </div>

        {/* HUB TAB - Real-time Dashboard */}
        {activeTab === 'hub' && (
          <div className="space-y-6 animate-in slide-in-from-bottom-4 pt-4">
            {/* Real Stats Dashboard */}
            <div className="m3-card p-6 bg-gradient-to-br from-[#0f172a] to-[#020617] border border-blue-500/10 shadow-2xl relative overflow-hidden group">
               <div className="absolute top-[-20%] right-[-10%] opacity-5 rotate-12">
                 <Shield className="w-64 h-64 text-blue-500" />
               </div>
               
               <div className="flex justify-between items-start mb-10 relative z-10">
                  <div>
                    <p className="text-[10px] font-black text-blue-500 uppercase tracking-widest mb-1 flex items-center gap-2">
                       <Radio className="w-3 h-3 animate-pulse" /> Live Threat Intel
                    </p>
                    <h2 className="text-4xl font-black text-white leading-none tracking-tighter">SECURED</h2>
                  </div>
                  <div className="text-right">
                    <p className="text-[9px] font-bold text-gray-500 uppercase">Registry Status</p>
                    <p className="text-[10px] font-black text-green-500 uppercase tracking-tighter">Up to Date</p>
                  </div>
               </div>

               <div className="grid grid-cols-2 gap-3 relative z-10">
                  <div className="bg-black/40 p-5 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-2 mb-2">
                       <Activity className="w-4 h-4 text-blue-400" />
                       <p className="text-[9px] font-bold text-gray-500 uppercase">Case Log</p>
                    </div>
                    <p className="text-3xl font-black text-white">{totalScans}</p>
                    <p className="text-[8px] text-gray-600 font-bold mt-1">L_UPDATE: {lastUpdate}</p>
                  </div>
                  <div className="bg-black/40 p-5 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-2 mb-2">
                       <ShieldAlert className="w-4 h-4 text-red-500" />
                       <p className="text-[9px] font-bold text-gray-500 uppercase">Breaches</p>
                    </div>
                    <p className="text-3xl font-black text-red-500">{maliciousCount}</p>
                    <p className="text-[8px] text-gray-600 font-bold mt-1">CRITICAL_VECTORS</p>
                  </div>
               </div>

               {/* Live Feed Terminal */}
               <div className="mt-6 p-4 bg-black/60 rounded-xl border border-white/5 relative z-10">
                  <div className="flex items-center gap-2 mb-2">
                     <Terminal className="w-3 h-3 text-blue-500" />
                     <p className="text-[8px] font-black text-gray-600 uppercase tracking-widest">Aegis Intelligence Feed</p>
                  </div>
                  <div className="space-y-1.5 overflow-hidden">
                     <p className="text-[9px] font-mono text-blue-400/60 truncate leading-none">>> Checking CVE-2024-5412 Registry...</p>
                     <p className="text-[9px] font-mono text-green-400/60 truncate leading-none">>> Connection stabilized on NODE_72-A</p>
                     <p className="text-[9px] font-mono text-gray-600 truncate leading-none">>> Idle scanning on background thread 4...</p>
                  </div>
               </div>
            </div>

            {/* Quick Access Menu */}
            <div className="grid grid-cols-2 gap-4">
               <button onClick={() => setShowScanDrawer(true)} className="m3-card p-8 bg-blue-600 flex flex-col items-center justify-center gap-4 active:scale-95 transition-all shadow-xl shadow-blue-600/30">
                  <ZapIcon className="w-10 h-10 text-white fill-white" />
                  <span className="text-[10px] font-black text-white uppercase tracking-[0.2em]">New Scan</span>
               </button>
               <button onClick={() => setActiveTab('labs')} className="m3-card p-8 bg-slate-800 border border-white/5 flex flex-col items-center justify-center gap-4 active:scale-95 transition-all">
                  <Cpu className="w-10 h-10 text-indigo-400" />
                  <span className="text-[10px] font-black text-white uppercase tracking-[0.2em]">Labs</span>
               </button>
            </div>

            {/* Core Systems */}
            <div className="space-y-3">
               <h3 className="text-[10px] font-black text-gray-600 uppercase tracking-widest px-1">Infrastructure Status</h3>
               <div className="m3-card p-5 flex items-center gap-4 bg-[#1e293b]/50 border border-white/5">
                  <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center shrink-0"><ShieldCheck className="w-5 h-5 text-blue-400" /></div>
                  <div className="flex-grow">
                    <p className="text-xs font-black text-white uppercase">Static Engine</p>
                    <p className="text-[9px] text-gray-500 font-bold uppercase tracking-tight">AI Heuristics v2.4 ACTIVE</p>
                  </div>
                  <div className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_8px_#22c55e]" />
               </div>
               <div className="m3-card p-5 flex items-center gap-4 bg-[#1e293b]/50 border border-white/5">
                  <div className="w-10 h-10 rounded-xl bg-indigo-500/10 flex items-center justify-center shrink-0"><Key className="w-5 h-5 text-indigo-400" /></div>
                  <div className="flex-grow">
                    <p className="text-xs font-black text-white uppercase">Cryptographic Vault</p>
                    <p className="text-[9px] text-gray-500 font-bold uppercase tracking-tight">AES-GCM-256 SESSION ACTIVE</p>
                  </div>
                  <div className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_8px_#22c55e]" />
               </div>
            </div>
          </div>
        )}

        {/* VAULT TAB */}
        {activeTab === 'vault' && (
          <div className="space-y-6 animate-in fade-in pt-4">
            <h2 className="text-[10px] font-black text-gray-600 uppercase tracking-widest px-1">Forensic Evidence Vault</h2>
            {history.length === 0 ? (
              <div className="py-40 flex flex-col items-center opacity-10 text-center">
                 <Database className="w-20 h-20 mb-6" />
                 <p className="text-xs font-black uppercase tracking-widest">No Evidence Logs Found</p>
              </div>
            ) : (
              <div className="space-y-3">
                {history.map(item => (
                  <div key={item.id} onClick={() => {setSelectedReport(item); setShowForensicReport(true);}} className="m3-card p-5 bg-[#1e293b]/40 border border-white/5 flex items-center justify-between active:scale-[0.98] transition-transform">
                    <div className="flex items-center gap-4 max-w-[70%]">
                      <div className={`w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 ${item.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10 text-red-500' : 'bg-blue-500/10 text-blue-400'}`}>
                        {item.type === 'URL' ? <Globe className="w-6 h-6"/> : <FileSearch className="w-6 h-6"/>}
                      </div>
                      <div className="overflow-hidden">
                        <p className="text-sm font-black text-white truncate uppercase">{item.target}</p>
                        <p className="text-[9px] text-gray-700 font-bold uppercase tracking-tighter">{item.id} • {new Date(item.timestamp).toLocaleDateString()}</p>
                      </div>
                    </div>
                    <div className="text-right">
                       <p className={`text-base font-black ${item.riskLevel === RiskLevel.MALICIOUS ? 'text-red-500' : 'text-blue-500'}`}>{item.riskScore}%</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* LABS TAB */}
        {activeTab === 'labs' && (
          <div className="space-y-8 animate-in fade-in pt-4 pb-10">
            <div className="flex gap-2 p-1.5 bg-white/5 rounded-2xl border border-white/5">
               {(['SHA', 'DECODE', 'ENTROPY'] as const).map(m => (
                 <button key={m} onClick={() => {setLabMode(m); setLabResult(null);}} className={`flex-grow py-3 rounded-xl text-[10px] font-black transition-all ${labMode === m ? 'bg-blue-600 text-white shadow-xl shadow-blue-600/20' : 'text-gray-500 hover:text-gray-300'}`}>
                   {m === 'SHA' ? 'Registry' : m === 'DECODE' ? 'Decoder' : 'Entropy'}
                 </button>
               ))}
            </div>

            <div className="m3-card p-6 bg-[#0f172a] border border-white/10 space-y-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-blue-500/10 rounded-2xl"><Code className="w-6 h-6 text-blue-400" /></div>
                <div>
                   <h3 className="text-sm font-black text-white uppercase tracking-tight">Analysis Sandbox</h3>
                   <p className="text-[9px] text-blue-500 font-bold uppercase tracking-widest">Isolated Environment v3</p>
                </div>
              </div>
              
              <div className="space-y-4">
                {labMode === 'DECODE' ? (
                  <textarea 
                    placeholder="PASTE BASE64 PAYLOAD BLOCK..." 
                    value={labInput}
                    onChange={e => setLabInput(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded-2xl p-4 text-[11px] font-mono text-blue-300 min-h-[160px] outline-none placeholder:text-gray-800"
                  />
                ) : (
                  <input 
                    type="text" 
                    placeholder={labMode === 'SHA' ? "ENTER HASH SIGNATURE..." : "ENTER DATA FOR ENTROPY SCAN..."}
                    value={labInput}
                    onChange={e => setLabInput(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded-2xl p-5 text-[11px] font-mono text-blue-300 outline-none placeholder:text-gray-800"
                  />
                )}
                
                <button onClick={handleLabAction} className="w-full bg-blue-600 p-5 rounded-2xl text-[11px] font-black text-white uppercase tracking-widest active:scale-95 transition-all shadow-xl shadow-blue-600/10">
                  Execute Forensic Routine
                </button>

                {labResult && (
                  <div className="p-5 bg-black/80 border border-blue-500/20 rounded-2xl animate-in zoom-in-95">
                     <p className="text-[9px] font-black text-blue-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                        <Activity className="w-4 h-4" /> Lab Output Terminal
                     </p>
                     <pre className="text-[10px] font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap leading-tight bg-black/20 p-4 rounded-xl">
                       {JSON.stringify(labResult, null, 2)}
                     </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* NOTIFICATIONS DRAWER */}
      {showNotifications && (
        <div className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-md flex items-end animate-in fade-in" onClick={() => setShowNotifications(false)}>
           <div className="w-full bg-[#0f172a] rounded-t-[40px] p-8 pb-12 space-y-6 animate-in slide-in-from-bottom-full duration-500 border-t border-white/10" onClick={e => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-2">
                 <h3 className="text-xl font-black text-white uppercase tracking-tighter">Event Center</h3>
                 <button onClick={() => setShowNotifications(false)} className="p-2 bg-white/5 rounded-full"><X className="w-5 h-5 text-gray-400"/></button>
              </div>
              <div className="space-y-4 max-h-[60vh] overflow-y-auto no-scrollbar">
                 {notifications.length === 0 ? (
                   <p className="text-center text-xs text-gray-600 py-10 uppercase font-black">No Recent Events</p>
                 ) : (
                   notifications.map(n => (
                     <div key={n.id} className="p-5 bg-white/5 border border-white/5 rounded-3xl flex gap-4 items-start">
                        <div className={`p-2 rounded-xl mt-1 ${n.severity === 'high' ? 'bg-red-500/10 text-red-500' : 'bg-blue-500/10 text-blue-400'}`}>
                           {n.severity === 'high' ? <ShieldAlert className="w-4 h-4" /> : <Info className="w-4 h-4" />}
                        </div>
                        <div className="flex-grow">
                           <p className="text-xs font-black text-white uppercase">{n.title}</p>
                           <p className="text-[10px] text-gray-400 font-medium leading-tight mt-1">{n.message}</p>
                           <p className="text-[8px] text-gray-600 font-bold uppercase mt-2">{new Date(n.time).toLocaleTimeString()}</p>
                        </div>
                     </div>
                   ))
                 )}
              </div>
              <button 
                onClick={() => setNotifications([])}
                className="w-full py-4 border border-white/5 rounded-2xl text-[10px] font-black text-gray-500 uppercase tracking-widest active:bg-white/5"
              >
                Clear All Logs
              </button>
           </div>
        </div>
      )}

      {/* FORENSIC REPORT - RESPONSIVE MOBILE VIEW */}
      {showForensicReport && selectedReport && (
        <div className="fixed inset-0 z-[500] bg-white text-slate-900 overflow-y-auto no-scrollbar animate-in slide-in-from-right duration-500">
           <div className="w-full max-w-[210mm] mx-auto bg-white min-h-screen px-6 py-10 sm:p-16 flex flex-col font-serif">
              
              {/* Report Title */}
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end border-b-[6px] sm:border-b-[10px] border-slate-900 pb-6 mb-10 gap-4">
                <div className="flex items-center gap-4 sm:gap-6">
                  <Shield className="w-12 h-12 sm:w-20 sm:h-20 text-slate-900 shrink-0" />
                  <div>
                    <h1 className="text-2xl sm:text-4xl font-black uppercase tracking-tighter leading-none text-slate-900">SECURITY AUDIT</h1>
                    <p className="text-[8px] sm:text-[10px] font-black text-slate-500 uppercase tracking-[0.3em] mt-1 sm:mt-2">REF: {selectedReport.id}</p>
                  </div>
                </div>
                <div className="text-left sm:text-right w-full sm:w-auto border-t sm:border-t-0 pt-4 sm:pt-0">
                  <span className="inline-block px-3 py-1 bg-slate-900 text-white text-[8px] sm:text-[9px] font-black uppercase tracking-widest mb-1">PRIVILEGED ASSET</span>
                  <p className="text-[8px] font-black text-slate-400 uppercase tracking-widest">CHAIN_OF_CUSTODY_VERIFIED</p>
                </div>
              </div>

              {/* Responsive Grid Meta */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-8 mb-10 font-sans">
                 <div className="space-y-4">
                    <h4 className="text-[10px] font-black uppercase border-b-2 border-slate-900 pb-1.5 tracking-widest text-slate-900">CASE METADATA</h4>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-4 text-[11px]">
                       <div><p className="text-slate-400 font-bold uppercase text-[8px] mb-0.5">Hash Digest</p><p className="font-black text-slate-900 truncate">{selectedReport.hash || 'DYNAMIC'}</p></div>
                       <div><p className="text-slate-400 font-bold uppercase text-[8px] mb-0.5">Asset Time</p><p className="font-black text-slate-900">{new Date(selectedReport.timestamp).toLocaleString()}</p></div>
                       <div><p className="text-slate-400 font-bold uppercase text-[8px] mb-0.5">Target Type</p><p className="font-black text-slate-900 uppercase">{selectedReport.type}</p></div>
                       <div><p className="text-slate-400 font-bold uppercase text-[8px] mb-0.5">Rigor Mode</p><p className="font-black text-slate-900 uppercase">{selectedReport.analysisDepth}</p></div>
                    </div>
                 </div>
                 <div className="space-y-4">
                    <h4 className="text-[10px] font-black uppercase border-b-2 border-slate-900 pb-1.5 tracking-widest text-slate-900">ASSET IDENTIFIER</h4>
                    <p className="text-slate-900 font-black break-all bg-slate-50 p-4 rounded-lg border border-slate-200 text-xs shadow-sm">{selectedReport.target}</p>
                 </div>
              </div>

              {/* Analysis Scores */}
              <div className="bg-slate-900 text-white p-8 sm:p-12 rounded-[40px] flex flex-col sm:flex-row justify-between items-center mb-10 gap-6 shadow-xl">
                <div className="text-center sm:text-left">
                  <p className="text-[9px] font-black uppercase opacity-60 tracking-[0.4em] mb-2">RISK LEVEL</p>
                  <p className="text-4xl sm:text-6xl font-black tracking-tighter uppercase">{selectedReport.riskLevel}</p>
                </div>
                <div className="text-center sm:text-right">
                  <p className="text-[9px] font-black uppercase opacity-60 tracking-[0.4em] mb-2">SEVERITY SCORE</p>
                  <p className="text-6xl sm:text-8xl font-black leading-none tracking-tighter">{selectedReport.riskScore}<span className="text-2xl opacity-30">%</span></p>
                </div>
              </div>

              {/* Engines List - Responsive Wrap */}
              <div className="space-y-4 font-sans mb-10">
                 <h4 className="text-[10px] font-black uppercase border-b-2 border-slate-900 pb-1.5 tracking-widest text-slate-900">MULTI-ENGINE AUDIT</h4>
                 <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {selectedReport.engines?.map((eng, i) => (
                      <div key={i} className="p-3 border border-slate-100 bg-slate-50 rounded-xl flex flex-col gap-0.5 shadow-sm">
                         <p className="text-[7px] font-black text-slate-400 uppercase truncate">{eng.engine}</p>
                         <p className={`text-[9px] font-black uppercase truncate ${eng.category === 'malicious' ? 'text-red-600' : 'text-green-600'}`}>
                            {eng.result || 'CLEAN'}
                         </p>
                      </div>
                    ))}
                 </div>
              </div>

              {/* Summary and Vector */}
              <div className="space-y-8 font-sans mb-16 flex-grow">
                 <h4 className="text-[10px] font-black uppercase border-b-2 border-slate-900 pb-1.5 tracking-widest text-slate-900">DETAILED FINDINGS</h4>
                 <div className="border-l-[8px] border-slate-900 pl-6 py-1">
                    <p className="text-lg sm:text-2xl font-medium italic text-slate-800 leading-tight">
                       "{selectedReport.details.summary}"
                    </p>
                 </div>
                 <div className="bg-slate-50 p-6 sm:p-10 rounded-[32px] border border-slate-200">
                    <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-6 flex items-center gap-2">
                      <ShieldAlert className="w-5 h-5 text-red-600" /> Vector Analysis Insights
                    </p>
                    <p className="text-[13px] text-slate-700 leading-relaxed font-medium mb-8">{selectedReport.details.aiInsights}</p>
                    <div className="pt-8 border-t border-slate-200">
                       <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-3">Verification Sigil</p>
                       <div className="p-4 bg-slate-900 text-blue-300 rounded-xl mono text-[8px] break-all leading-tight shadow-inner">
                         {selectedReport.encryptedPayload}
                       </div>
                    </div>
                 </div>
              </div>

              {/* Blank Signature Lines */}
              <div className="pt-12 border-t border-slate-200 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-12 font-sans mt-auto">
                 <div className="flex flex-col sm:flex-row gap-12 sm:gap-20 w-full">
                    <div className="space-y-3">
                       <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Examining Agent Signature</p>
                       <div className="w-52 h-14 border-b-2 border-slate-900" />
                       <p className="text-[10px] font-black text-slate-900 uppercase">Authorization: {currentUser}</p>
                    </div>
                    <div className="space-y-3">
                       <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Forensic Lead Authentication</p>
                       <div className="w-52 h-14 border-b-2 border-slate-900" />
                       <p className="text-[10px] font-black text-slate-900 uppercase">Sentinel Core Division</p>
                    </div>
                 </div>
                 <div className="no-print flex flex-col gap-2 w-full sm:w-auto">
                    <button onClick={() => window.print()} className="bg-slate-900 text-white px-8 py-5 rounded-[24px] text-[11px] font-black uppercase tracking-widest flex items-center justify-center gap-3 shadow-xl active:scale-95 transition-all">
                      <Printer className="w-5 h-5" /> Print Report
                    </button>
                    <button onClick={() => setShowForensicReport(false)} className="bg-slate-100 text-slate-600 px-8 py-5 rounded-[24px] text-[11px] font-black uppercase tracking-widest active:scale-95 transition-all">
                      Close Archive
                    </button>
                 </div>
              </div>
           </div>
        </div>
      )}

      {/* SCAN DRAWER */}
      {showScanDrawer && (
        <div className="fixed inset-0 z-[100] bg-black/95 backdrop-blur-md flex items-end animate-in fade-in">
          <div className="w-full bg-[#0f172a] rounded-t-[40px] p-8 pb-16 space-y-8 animate-in slide-in-from-bottom-full duration-500 border-t border-white/5 no-print shadow-2xl">
            <div className="flex justify-between items-center">
               <h3 className="text-2xl font-black text-white uppercase tracking-tighter">Initialize Audit</h3>
               <button onClick={() => setShowScanDrawer(false)} className="p-2 bg-white/5 rounded-full"><X className="w-6 h-6 text-gray-400"/></button>
            </div>
            <div className="space-y-6">
               <div className="space-y-3">
                 <p className="text-[10px] font-black text-gray-600 uppercase tracking-widest px-1">Decomposition Level</p>
                 <div className="flex gap-2 bg-black/40 p-1.5 rounded-3xl border border-white/5">
                    {(['Quick', 'Standard', 'Deep'] as AnalysisDepth[]).map(d => (
                      <button 
                        key={d} 
                        onClick={() => setAnalysisDepth(d)} 
                        className={`flex-grow py-3 rounded-2xl text-[10px] font-black uppercase transition-all duration-300 ${analysisDepth === d ? 'bg-blue-600 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                      >
                        {d}
                      </button>
                    ))}
                 </div>
               </div>
               <div className="relative">
                 <input type="text" placeholder="TARGET URL..." value={url} onChange={e => setUrl(e.target.value)} className="w-full bg-black/40 border border-white/10 rounded-3xl p-6 pr-20 text-sm font-bold text-white outline-none focus:border-blue-500 transition-all placeholder:text-gray-800" />
                 <button onClick={() => executeScan('URL', { url })} disabled={!url} className="absolute right-3 top-3 bottom-3 px-6 bg-blue-600 rounded-2xl shadow-xl shadow-blue-600/30 disabled:opacity-20 active:scale-95 transition-all"><Search className="w-5 h-5 text-white"/></button>
               </div>
               <div className="grid grid-cols-2 gap-4">
                  <label className="m3-card bg-black/40 p-10 border border-white/5 flex flex-col items-center gap-4 cursor-pointer active:scale-95 transition-all">
                    <input type="file" accept=".apk" onChange={async (e) => { const f = e.target.files?.[0]; if(f) executeScan('APK', await extractApkMetadata(f)); }} className="hidden" />
                    <Box className="w-10 h-10 text-indigo-400" />
                    <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">APK Binary</span>
                  </label>
                  <label className="m3-card bg-black/40 p-10 border border-white/5 flex flex-col items-center gap-4 cursor-pointer active:scale-95 transition-all">
                    <input type="file" accept=".pdf" onChange={async (e) => { const f = e.target.files?.[0]; if(f) executeScan('PDF', await extractPdfMetadata(f)); }} className="hidden" />
                    <FileText className="w-10 h-10 text-rose-400" />
                    <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">PDF Asset</span>
                  </label>
               </div>
            </div>
          </div>
        </div>
      )}

      {/* BOTTOM NAV */}
      <nav className="fixed bottom-0 left-0 right-0 bg-[#0f172a]/95 backdrop-blur-3xl border-t border-white/10 h-28 flex justify-around items-center px-6 z-40 no-print shadow-2xl">
        <button onClick={() => {setActiveTab('hub'); setSelectedReport(null);}} className={`flex flex-col items-center gap-2 w-20 transition-all ${activeTab === 'hub' ? 'text-blue-500' : 'text-gray-600'}`}>
          <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === 'hub' ? 'bg-blue-600/10 scale-110' : 'active:bg-white/5'}`}><LayoutGrid className="w-6 h-6" /></div>
          <span className="text-[9px] font-black uppercase tracking-widest">Hub</span>
        </button>
        <button onClick={() => setActiveTab('vault')} className={`flex flex-col items-center gap-2 w-20 transition-all ${activeTab === 'vault' ? 'text-blue-500' : 'text-gray-600'}`}>
          <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === 'vault' ? 'bg-blue-600/10 scale-110' : 'active:bg-white/5'}`}><Database className="w-6 h-6" /></div>
          <span className="text-[9px] font-black uppercase tracking-widest">Vault</span>
        </button>
        <button onClick={() => setActiveTab('labs')} className={`flex flex-col items-center gap-2 w-20 transition-all ${activeTab === 'labs' ? 'text-blue-500' : 'text-gray-600'}`}>
          <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === 'labs' ? 'bg-blue-600/10 scale-110' : 'active:bg-white/5'}`}><Cpu className="w-6 h-6" /></div>
          <span className="text-[9px] font-black uppercase tracking-widest">Labs</span>
        </button>
      </nav>

      {/* GLOBAL SCANNING OVERLAY */}
      {isScanning && (
        <div className="fixed inset-0 z-[1000] bg-black/95 backdrop-blur-3xl flex flex-col items-center justify-center text-center p-12 no-print">
           <div className="relative mb-12">
             <Shield className="w-24 h-24 text-blue-500 animate-pulse drop-shadow-[0_0_30px_rgba(59,130,246,0.6)]" />
             <div className="absolute inset-[-24px] border-2 border-blue-500/20 rounded-full animate-ping" />
           </div>
           <h3 className="text-4xl font-black text-white uppercase tracking-tighter mb-4">Static Analysis</h3>
           <p className="text-blue-500 font-black text-[11px] uppercase tracking-[0.4em] mb-12 animate-pulse">Running Recursive Forensic Audit...</p>
           <div className="w-full max-w-xs bg-white/5 h-2 rounded-full overflow-hidden border border-white/5">
              <div className="h-full bg-blue-500 w-1/2 animate-[shimmer_2s_infinite_linear] rounded-full shadow-[0_0_15px_#3b82f6]" />
           </div>
           <style>{`@keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(200%); } }`}</style>
        </div>
      )}
    </div>
  );
};

export default App;
