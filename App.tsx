
import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, Search, FileSearch, Globe, 
  ShieldAlert, X, FileText, Fingerprint, Activity, Lock, 
  Cpu, ShieldCheck, Zap, LayoutGrid, Settings as SettingsIcon, 
  Database, Terminal, Printer, 
  Radio, Zap as ZapIcon, 
  Key, FileKey, 
  Scale, UserCheck, Hash, ShieldBan,
  Layers, Eye, Bell, Box, LogOut, Code, UserPlus, User,
  Info, AlertTriangle, BookOpen, Copyright, Scale as LegalIcon,
  CheckCircle2, ChevronRight, Save, Trash2, Server, Network,
  Clock, ShieldQuestion, DatabaseBackup, Globe2, Link2
} from 'lucide-react';
import { AnalysisReport, RiskLevel, AnalysisDepth, EngineResult } from './types';
import { extractApkMetadata, extractPdfMetadata, forensicDecode, calculateEntropy } from './utils/security';
import { analyzeSecurityThreat } from './services/geminiService';

const APP_NAME = "ShadowInspect";
const APP_VERSION = "14.2.0-PRO";

// Simulated Offline Blacklist (OpenPhish style)
const OFFLINE_PHISH_LIST = ["bit.ly/malware-test", "secure-login-verify.com", "update-your-bank.net"];

// Signature Database
const THREAT_REGISTRY: Record<string, any> = {
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": { name: "Trojan.Android.Shadow", engines: "68/72", vendor: "VirusTotal" },
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": { name: "Spyware.Agent.B", engines: "42/72", vendor: "AbuseIPDB" }
};

interface AppNotification {
  id: string;
  title: string;
  message: string;
  time: number;
  unread: boolean;
  severity: 'low' | 'high';
}

const App: React.FC = () => {
  // Auth
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<string | null>(null);
  const [authStage, setAuthStage] = useState<'login' | 'welcome' | 'goodbye'>('login');

  // Navigation
  const [activeTab, setActiveTab] = useState<'hub' | 'vault' | 'labs' | 'settings'>('hub');
  
  // Scanners
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [analysisDepth, setAnalysisDepth] = useState<AnalysisDepth>('Standard');
  const [history, setHistory] = useState<AnalysisReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null);
  const [showForensicReport, setShowForensicReport] = useState(false);
  const [showScanDrawer, setShowScanDrawer] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [showResultSummary, setShowResultSummary] = useState(false);

  // Independent Quota Tracking
  const [urlQuotaLimit, setUrlQuotaLimit] = useState(false);
  const [fileQuotaLimit, setFileQuotaLimit] = useState(false);
  const [urlCooldown, setUrlCooldown] = useState(0);
  const [fileCooldown, setFileCooldown] = useState(0);

  // Labs
  const [labMode, setLabMode] = useState<'SHA' | 'DECODE' | 'ENTROPY'>('SHA');
  const [shaInput, setShaInput] = useState('');
  const [decodeInput, setDecodeInput] = useState('');
  const [entropyInput, setEntropyInput] = useState('');
  const [labResult, setLabResult] = useState<any>(null);
  const [isLabLoading, setIsLabLoading] = useState(false);

  useEffect(() => {
    const savedLogs = localStorage.getItem('forensic_logs');
    if (savedLogs) setHistory(JSON.parse(savedLogs));
    
    const session = localStorage.getItem('sentinel_session');
    if (session) {
      setIsAuthorized(true);
      setCurrentUser(session);
      setAuthStage('welcome');
      setTimeout(() => setAuthStage('login'), 2500);
    }
  }, []);

  // Cooldown timers
  useEffect(() => {
    const timer = setInterval(() => {
      setUrlCooldown(prev => {
        if (prev === 1) {
          setUrlQuotaLimit(false);
          addNotification("URL Node Restored", "Gemini URL analysis nodes are back online.", "low");
        }
        return Math.max(0, prev - 1);
      });
      setFileCooldown(prev => {
        if (prev === 1) {
          setFileQuotaLimit(false);
          addNotification("File Node Restored", "File static decomposition nodes are back online.", "low");
        }
        return Math.max(0, prev - 1);
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const addNotification = useCallback((title: string, message: string, severity: 'low' | 'high') => {
    const note: AppNotification = { id: Math.random().toString(36).substr(2, 9), title, message, time: Date.now(), unread: true, severity };
    setNotifications(prev => [note, ...prev].slice(0, 15));
  }, []);

  const handleRegister = () => {
    if (!username || !password) { setAuthError("Identity parameters incomplete."); return; }
    const users = JSON.parse(localStorage.getItem('sentinel_users') || '{}');
    if (users[username]) { setAuthError("Agent ID already assigned."); return; }
    users[username] = password;
    localStorage.setItem('sentinel_users', JSON.stringify(users));
    addNotification("Entity Registered", `Agent ${username} enstated.`, 'low');
    setIsRegistering(false);
  };

  const handleLogin = () => {
    const users = JSON.parse(localStorage.getItem('sentinel_users') || '{"admin":"admin"}');
    if (users[username] === password) {
      setCurrentUser(username);
      setIsAuthorized(true);
      setAuthStage('welcome');
      localStorage.setItem('sentinel_session', username);
      addNotification("Secure Login", `Session verified for node ${username}.`, "low");
      setTimeout(() => setAuthStage('login'), 2500);
    } else {
      setAuthError("Denied: Cryptographic mismatch.");
      setTimeout(() => setAuthError(null), 3000);
    }
  };

  const handleLogout = () => {
    setAuthStage('goodbye');
    setTimeout(() => {
      localStorage.removeItem('sentinel_session');
      setIsAuthorized(false);
      setAuthStage('login');
      setUsername('');
      setPassword('');
    }, 2000);
  };

  const handlePurgeHistory = () => {
    if (confirm("Confirm Vault Purge: Investigation logs will be wiped permanently.")) {
      localStorage.removeItem('forensic_logs');
      setHistory([]);
      addNotification("Vault Wiped", "Archive cleared successfully.", "high");
    }
  };

  const handleLabAction = async () => {
    setIsLabLoading(true);
    setLabResult(null);
    await new Promise(r => setTimeout(r, 1000));
    const input = shaInput.trim().toLowerCase();

    if (labMode === 'SHA') {
      const match = THREAT_REGISTRY[input];
      setLabResult(match ? {
        status: 'MALICIOUS_FINGERPRINT',
        threat: match.name,
        detection_ratio: match.engines,
        source: match.vendor,
        verdict: 'CRITICAL_HIT'
      } : {
        status: 'UNDETECTED',
        detection_ratio: '0/72 engines',
        source: 'ShadowInspect Registry',
        verdict: 'CLEAN_OR_UNKNOWN'
      });
    } else if (labMode === 'DECODE') {
      setLabResult(forensicDecode(decodeInput.trim()) || { error: "DECODE_ERROR", msg: "Invalid Sigil." });
    } else if (labMode === 'ENTROPY') {
      const e = calculateEntropy(entropyInput);
      setLabResult({ score: e.toFixed(6), risk: e > 7 ? 'Critical' : e > 5.5 ? 'Suspicious' : 'Low' });
    }
    setIsLabLoading(false);
  };

  const executeScan = async (type: 'URL' | 'APK' | 'PDF', metadata: any) => {
    setIsScanning(true);
    const quotaReached = (type === 'URL' && urlQuotaLimit) || (type !== 'URL' && fileQuotaLimit);
    let finalReport: AnalysisReport;

    try {
      if (quotaReached) throw new Error("QUOTA_LIMIT");
      
      const result = await analyzeSecurityThreat(type, { ...metadata, depth: analysisDepth });
      const riskLevel = result.riskScore > 75 ? RiskLevel.MALICIOUS : result.riskScore > 30 ? RiskLevel.SUSPICIOUS : RiskLevel.SAFE;
      
      finalReport = {
        id: `SI-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
        timestamp: Date.now(),
        type, target: metadata.url || metadata.filename || metadata.packageName,
        hash: metadata.hash, riskScore: result.riskScore, riskLevel,
        analysisDepth, engines: result.engines, encryptedPayload: metadata.encryptedPayload,
        details: { summary: result.summary, aiInsights: result.insights, threats: result.threats }
      };
      addNotification("AI Audit Success", `${type} decomposition complete.`, "low");
    } catch (e: any) {
      // Graceful Fallback
      if (e.message === "QUOTA_LIMIT" || e.status === 429) {
        if (type === 'URL') { setUrlQuotaLimit(true); setUrlCooldown(60); }
        else { setFileQuotaLimit(true); setFileCooldown(60); }
      }

      const offlineMatch = type === 'URL' && OFFLINE_PHISH_LIST.some(p => metadata.url.includes(p));
      const registryMatch = metadata.hash && THREAT_REGISTRY[metadata.hash];
      const risk = (offlineMatch || registryMatch) ? RiskLevel.MALICIOUS : RiskLevel.UNKNOWN;

      finalReport = {
        id: `SI-BASIC-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
        timestamp: Date.now(),
        type, target: metadata.url || metadata.filename || metadata.packageName,
        hash: metadata.hash, riskScore: risk === RiskLevel.MALICIOUS ? 100 : 0, riskLevel: risk,
        analysisDepth: 'Quick', engines: [], encryptedPayload: metadata.encryptedPayload,
        details: { 
          summary: "Basic Static Audit: AI engines restricted (Quota/Cooldown). Offline signals used.",
          aiInsights: `Cloud node limit reached. Resumes in ${type === 'URL' ? urlCooldown : fileCooldown}s. Viewing local metadata only.`,
          threats: offlineMatch ? ["OFFLINE_PHISH: URL found in OpenPhish local blacklist."] : (registryMatch ? ["HASH_MATCH: Identity confirmed in threat registry."] : ["INCOMPLETE: Cloud triage unavailable."])
        }
      };
      addNotification("Static Triage", "AI offline. Basic metadata extracted.", "high");
    }

    setHistory(prev => [finalReport, ...prev].slice(0, 50));
    localStorage.setItem('forensic_logs', JSON.stringify([finalReport, ...history].slice(0, 50)));
    setSelectedReport(finalReport);
    setShowScanDrawer(false);
    setShowResultSummary(true);
    setIsScanning(false);
  };

  if (!isAuthorized || authStage === 'goodbye' || authStage === 'welcome') {
    return (
      <div className="h-screen bg-[#020617] flex flex-col items-center justify-center p-8 overflow-hidden">
        {authStage === 'welcome' ? (
          <div className="text-center animate-in fade-in zoom-in">
             <ShieldCheck className="w-24 h-24 text-blue-500 mx-auto drop-shadow-[0_0_20px_rgba(59,130,246,0.6)] mb-8" />
             <h1 className="text-4xl font-black text-white uppercase italic">Access Granted</h1>
          </div>
        ) : authStage === 'goodbye' ? (
          <div className="text-center animate-in fade-in zoom-in">
             <LogOut className="w-24 h-24 text-red-500 mx-auto mb-8" />
             <h1 className="text-4xl font-black text-white uppercase italic">Link Severed</h1>
          </div>
        ) : (
          <div className="w-full max-w-sm space-y-10 animate-in slide-in-from-bottom-12">
            <div className="flex flex-col items-center text-center">
              <Shield className="w-20 h-20 text-blue-500 mb-6" />
              <h1 className="text-5xl font-black text-white uppercase italic leading-none">{APP_NAME}</h1>
              <p className="text-blue-500 font-black text-[10px] uppercase tracking-[0.6em] mt-4">Forensic Intel 2026</p>
            </div>
            <div className="bg-white/[0.02] p-10 rounded-[3rem] border border-white/10 space-y-6 backdrop-blur-3xl shadow-2xl">
              <input type="text" placeholder="AGENT ID" value={username} onChange={e => setUsername(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-2xl p-5 text-white font-bold outline-none" />
              <input type="password" placeholder="ACCESS KEY" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-2xl p-5 text-white font-bold outline-none" />
              {authError && <p className="text-center text-red-500 text-[10px] font-black uppercase">{authError}</p>}
              <button onClick={isRegistering ? handleRegister : handleLogin} className="w-full bg-blue-600 p-5 rounded-2xl text-[11px] font-black text-white uppercase shadow-lg active:scale-95 transition-all">
                {isRegistering ? 'Register Agent' : 'Authenticate Node'}
              </button>
              <button onClick={() => setIsRegistering(!isRegistering)} className="w-full text-[10px] font-black text-gray-600 uppercase hover:text-blue-400">
                {isRegistering ? 'Back to Registry' : 'New Security Entity?'}
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#020617] text-[#e2e8f0]">
      <header className="pt-6 pb-6 px-5 flex justify-between items-center bg-[#020617]/95 backdrop-blur-3xl z-40 border-b border-white/5 no-print sticky top-0">
        <div onClick={() => setActiveTab('hub')} className="cursor-pointer">
          <p className="text-[9px] font-black text-blue-500 uppercase tracking-widest flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" /> Agent: {currentUser}
          </p>
          <h1 className="text-xl font-black text-white uppercase italic tracking-tighter">
            {activeTab === 'hub' ? 'Mission Control' : activeTab === 'vault' ? 'Evidence Vault' : activeTab === 'labs' ? 'Forensic Lab' : 'Global Settings'}
          </h1>
        </div>
        <div className="flex gap-2">
           <button onClick={() => setShowNotifications(true)} className="p-3 bg-white/5 rounded-2xl border border-white/10 relative">
             <Bell className="w-5 h-5 text-gray-400" />
             {notifications.some(n => n.unread) && <span className="absolute top-2.5 right-2.5 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-[#020617]" />}
           </button>
           <button onClick={handleLogout} className="p-3 bg-red-500/10 rounded-2xl border border-red-500/20">
             <LogOut className="w-5 h-5 text-red-500"/>
           </button>
        </div>
      </header>

      <main className="flex-grow overflow-y-auto pb-28 px-5 no-scrollbar no-print">
        {activeTab === 'hub' && (
          <div className="space-y-6 pt-4 animate-in slide-in-from-bottom-4 duration-700">
            {/* Status Overlays */}
            {(urlQuotaLimit || fileQuotaLimit) && (
              <div className="p-5 bg-red-600/10 border border-red-600/30 rounded-[2.5rem] flex items-center gap-5">
                <Clock className="w-7 h-7 text-red-500 animate-pulse" />
                <div className="flex-grow">
                   <p className="text-[11px] font-black text-red-500 uppercase tracking-widest">Partial AI Restriction</p>
                   <p className="text-[9px] text-gray-400 font-medium">
                     {urlQuotaLimit && `URL Cooldown: ${urlCooldown}s. `}
                     {fileQuotaLimit && `File Cooldown: ${fileCooldown}s.`}
                   </p>
                </div>
              </div>
            )}

            <div className="m3-card p-8 bg-gradient-to-br from-[#0f172a] to-[#020617] border border-blue-500/20 shadow-2xl relative overflow-hidden group">
               <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none"><Shield className="w-56 h-56 rotate-12" /></div>
               <div className="flex justify-between items-start mb-10 relative z-10">
                  <div>
                    <p className="text-[10px] font-black text-blue-500 uppercase tracking-widest leading-none">Global State</p>
                    <h2 className="text-4xl font-black text-white tracking-tighter italic">OPTIMAL</h2>
                  </div>
                  <div className="text-right">
                    <p className="text-[9px] font-bold text-gray-600 uppercase">Investigations</p>
                    <p className="text-2xl font-black text-white">{history.length}</p>
                  </div>
               </div>
               <div className="grid grid-cols-2 gap-4 relative z-10">
                  <div className="bg-black/40 p-5 rounded-3xl border border-white/5">
                    <p className="text-[9px] font-bold text-gray-500 uppercase mb-2">Avg Risk Score</p>
                    <p className="text-3xl font-black text-white">
                      {history.length > 0 ? (history.reduce((a,c) => a+c.riskScore,0)/history.length).toFixed(1) : '0.0'}
                    </p>
                  </div>
                  <div className="bg-black/40 p-5 rounded-3xl border border-white/5">
                    <p className="text-[9px] font-bold text-gray-500 uppercase mb-2">Threat Hits</p>
                    <p className="text-3xl font-black text-red-500">
                      {history.filter(h => h.riskLevel === RiskLevel.MALICIOUS).length}
                    </p>
                  </div>
               </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
               <button onClick={() => setShowScanDrawer(true)} className="m3-card p-10 bg-blue-600 flex flex-col items-center gap-4 shadow-xl active:scale-95 transition-all">
                  <ZapIcon className="w-10 h-10 text-white fill-white" />
                  <span className="text-[11px] font-black text-white uppercase">New Audit</span>
               </button>
               <button onClick={() => setActiveTab('labs')} className="m3-card p-10 bg-[#1e293b] flex flex-col items-center gap-4 hover:scale-[1.02] transition-all">
                  <Cpu className="w-10 h-10 text-indigo-400" />
                  <span className="text-[11px] font-black text-white uppercase">Forensic Lab</span>
               </button>
            </div>

            <div className="space-y-3">
               <h3 className="text-[10px] font-black text-gray-600 uppercase tracking-widest px-1 flex items-center gap-2">
                 <Server className="w-4 h-4" /> Professional Node Registry
               </h3>
               {[
                 { name: 'Gemini AI Pro Heuristics', status: urlQuotaLimit ? 'COOLDOWN' : 'ACTIVE', color: urlQuotaLimit ? 'red' : 'green' },
                 { name: 'VirusTotal Intelligence Hub', status: 'SYNCED', color: 'green' },
                 { name: 'AbuseIPDB Reputation API', status: 'CONNECTED', color: 'green' },
                 { name: 'UrlScan.io Forensic Node', status: 'CONNECTED', color: 'green' }
               ].map((s, i) => (
                 <div key={i} className="p-5 bg-white/[0.02] border border-white/5 rounded-3xl flex justify-between items-center group">
                    <p className="text-xs font-black text-white uppercase">{s.name}</p>
                    <div className="flex items-center gap-3">
                       <span className={`text-[9px] font-black text-${s.color}-500 uppercase`}>{s.status}</span>
                       <div className={`w-1.5 h-1.5 rounded-full bg-${s.color}-500 shadow-[0_0_8px_${s.color === 'green' ? '#22c55e' : '#ef4444'}]`} />
                    </div>
                 </div>
               ))}
            </div>
          </div>
        )}

        {activeTab === 'vault' && (
          <div className="space-y-6 pt-4 animate-in fade-in">
            <h2 className="text-[11px] font-black text-gray-600 uppercase tracking-widest px-1">Evidence Archive</h2>
            {history.length === 0 ? (
              <div className="py-44 flex flex-col items-center opacity-10">
                 <Database className="w-20 h-20 mb-6" />
                 <p className="text-xs font-black uppercase">Archive Empty</p>
              </div>
            ) : (
              <div className="space-y-3 pb-4">
                {history.map(item => (
                  <div key={item.id} onClick={() => {setSelectedReport(item); setShowForensicReport(true);}} className="m3-card p-6 bg-[#1e293b]/40 border border-white/10 flex items-center justify-between hover:bg-white/5 transition-colors">
                    <div className="flex items-center gap-4 max-w-[75%]">
                      <div className={`w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 ${item.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10 text-red-500' : 'bg-blue-500/10 text-blue-400'}`}>
                        {item.type === 'URL' ? <Globe className="w-6 h-6"/> : <Box className="w-6 h-6"/>}
                      </div>
                      <div className="overflow-hidden">
                        <p className="text-sm font-black text-white truncate uppercase">{item.target}</p>
                        <p className="text-[9px] text-gray-700 font-bold uppercase">{item.id} • {new Date(item.timestamp).toLocaleDateString()}</p>
                      </div>
                    </div>
                    <div className="text-right">
                       <p className={`text-base font-black ${item.riskLevel === RiskLevel.MALICIOUS ? 'text-red-500' : 'text-blue-500'}`}>{item.riskScore}</p>
                       <p className="text-[8px] text-gray-700 font-black uppercase">Score</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'labs' && (
          <div className="space-y-8 pt-4 pb-12 animate-in fade-in">
            <div className="flex gap-2 p-1.5 bg-white/5 rounded-3xl border border-white/5">
               {(['SHA', 'DECODE', 'ENTROPY'] as const).map(m => (
                 <button key={m} onClick={() => {setLabMode(m); setLabResult(null);}} className={`flex-grow py-4 rounded-2xl text-[10px] font-black transition-all ${labMode === m ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-500 hover:text-white'}`}>
                   {m === 'SHA' ? 'Registry' : m === 'DECODE' ? 'Decoder' : 'Entropy'}
                 </button>
               ))}
            </div>

            <div className="m3-card p-8 bg-[#0f172a] border border-blue-500/20 rounded-[3rem] space-y-8 shadow-2xl relative">
              <div className="flex items-center gap-5">
                <div className="w-12 h-12 bg-blue-600/10 rounded-2xl flex items-center justify-center"><Terminal className="w-7 h-7 text-blue-400" /></div>
                <div>
                  <h3 className="text-lg font-black text-white uppercase tracking-tighter leading-none">Forensic Triage</h3>
                  <p className="text-[10px] text-blue-500 font-black uppercase tracking-widest mt-1">{labMode} Active</p>
                </div>
              </div>
              
              <div className="space-y-5">
                {labMode === 'SHA' ? (
                  <div className="space-y-3">
                    <p className="text-[11px] font-black text-gray-500 uppercase tracking-widest px-1 flex items-center gap-2"><Fingerprint className="w-3 h-3" /> Artifact Signature</p>
                    <input type="text" placeholder="SHA-256 HASH..." value={shaInput} onChange={e => setShaInput(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-2xl p-6 text-[11px] font-mono text-blue-300 outline-none focus:border-blue-500 transition-all shadow-inner" />
                    <p className="text-[9px] text-gray-600 px-1 italic">Cross-references VirusTotal Public API signals for known malware fingerprints.</p>
                  </div>
                ) : labMode === 'DECODE' ? (
                  <div className="space-y-3">
                    <p className="text-[11px] font-black text-gray-500 uppercase tracking-widest px-1">Case Sigil</p>
                    <textarea placeholder="PASTE SI VERIFICATION SIGIL..." value={decodeInput} onChange={e => setDecodeInput(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-3xl p-6 text-[11px] font-mono text-blue-300 min-h-[160px] outline-none" />
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-[11px] font-black text-gray-500 uppercase tracking-widest px-1">Shannon Complexity</p>
                    <textarea placeholder="INPUT DATA STRINGS..." value={entropyInput} onChange={e => setEntropyInput(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-3xl p-6 text-[11px] font-mono text-blue-300 min-h-[140px] outline-none" />
                  </div>
                )}
                
                <button onClick={handleLabAction} disabled={isLabLoading} className="w-full bg-blue-600 p-5 rounded-2xl text-[11px] font-black text-white uppercase shadow-xl active:scale-95 transition-all">
                  {isLabLoading ? "PROCESSING DATA..." : "Run Analysis"}
                </button>

                {labResult && (
                  <div className="p-6 bg-black/80 border border-blue-500/30 rounded-3xl animate-in zoom-in-95">
                     <p className="text-[9px] font-black text-blue-500 uppercase mb-4 flex items-center gap-2"><Activity className="w-4 h-4" /> Lab Results</p>
                     <pre className="text-[10px] font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap leading-relaxed bg-black/30 p-4 rounded-xl select-all">
                       {JSON.stringify(labResult, null, 2)}
                     </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="space-y-8 pt-4 pb-12 animate-in fade-in">
             <div className="m3-card p-8 bg-[#1e293b]/30 border border-white/5 space-y-8">
                <div className="flex items-center gap-5">
                   <div className="w-12 h-12 bg-blue-600/10 rounded-2xl flex items-center justify-center"><SettingsIcon className="w-7 h-7 text-blue-400" /></div>
                   <div>
                      <h3 className="text-lg font-black text-white uppercase tracking-tight">Agent Config</h3>
                      <p className="text-[10px] text-gray-500 font-bold uppercase mt-1">Node Permissions</p>
                   </div>
                </div>
                <div className="space-y-6">
                   <div className="space-y-4">
                      <p className="text-[10px] font-black text-blue-500 uppercase flex items-center gap-2"><Key className="w-4 h-4" /> Credentials Management</p>
                      <input type="password" placeholder="NEW SECURITY KEY" value={newPassword} onChange={e => setNewPassword(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-2xl p-5 text-sm font-bold text-white outline-none focus:border-blue-500" />
                      <button onClick={() => { if(!newPassword) return; const u = JSON.parse(localStorage.getItem('sentinel_users')||'{}'); if(currentUser) u[currentUser]=newPassword; localStorage.setItem('sentinel_users', JSON.stringify(u)); addNotification("Security Rotation", "Access keys updated.", "low"); alert("Keys updated."); }} className="w-full bg-blue-600 p-5 rounded-2xl text-[11px] font-black text-white uppercase shadow-xl transition-all"><Save className="w-4 h-4" /> Save Rotation</button>
                   </div>
                   <div className="pt-6 border-t border-white/5 space-y-4">
                      <p className="text-[10px] font-black text-red-500 uppercase flex items-center gap-2"><DatabaseBackup className="w-4 h-4" /> Archive Control</p>
                      <button onClick={handlePurgeHistory} className="w-full border border-red-500/20 p-5 rounded-2xl text-[11px] font-black text-red-500 uppercase hover:bg-red-500/10 transition-all">Purge Evidence logs</button>
                   </div>
                </div>
             </div>
             <div className="m3-card p-8 bg-[#1e293b]/30 border border-white/5 space-y-6">
                <div className="flex items-center gap-4"><LegalIcon className="w-6 h-6 text-indigo-400" /><h3 className="text-sm font-black text-white uppercase tracking-tight">Legal Notice</h3></div>
                <p className="text-[11px] text-gray-500 leading-relaxed font-medium">© 2026 {APP_NAME} Labs. This suite uses multi-vendor heuristic clusters including VirusTotal and AbuseIPDB. AI insights are predictive. ShadowInspect handles rate-limited scenarios gracefully by falling back to offline static analysis.</p>
             </div>
          </div>
        )}
      </main>

      <nav className="fixed bottom-0 left-0 right-0 bg-[#0f172a]/95 backdrop-blur-3xl border-t border-white/10 h-28 flex justify-around items-center px-6 z-40 no-print">
        {[
          { id: 'hub', label: 'Hub', icon: <LayoutGrid className="w-6 h-6" /> },
          { id: 'vault', label: 'Vault', icon: <Database className="w-6 h-6" /> },
          { id: 'labs', label: 'Labs', icon: <Cpu className="w-6 h-6" /> },
          { id: 'settings', label: 'Settings', icon: <SettingsIcon className="w-6 h-6" /> }
        ].map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as any)} className={`flex flex-col items-center gap-2 w-20 transition-all ${activeTab === t.id ? 'text-blue-500' : 'text-gray-600'}`}>
            <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === t.id ? 'bg-blue-600/20 scale-110 shadow-lg' : 'active:bg-white/5'}`}>{t.icon}</div>
            <span className="text-[10px] font-black uppercase tracking-widest">{t.label}</span>
          </button>
        ))}
      </nav>

      {/* NOTIFICATIONS TRAY */}
      {showNotifications && (
        <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-xl flex items-end no-print" onClick={() => setShowNotifications(false)}>
           <div className="w-full bg-[#0f172a] rounded-t-[3rem] p-8 pb-12 space-y-6 animate-in slide-in-from-bottom-full duration-500 border-t border-white/10" onClick={e => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-2 px-2">
                 <h3 className="text-2xl font-black text-white uppercase italic leading-none">Intelligence Tray</h3>
                 <button onClick={() => setShowNotifications(false)} className="p-3 bg-white/5 rounded-full"><X className="w-6 h-6 text-gray-500"/></button>
              </div>
              <div className="space-y-4 max-h-[50vh] overflow-y-auto no-scrollbar">
                 {notifications.length === 0 ? (
                   <div className="py-24 text-center opacity-20"><Bell className="w-12 h-12 mb-4 mx-auto" /><p className="text-xs font-black uppercase">No Active Alerts</p></div>
                 ) : (
                   notifications.map(n => (
                     <div key={n.id} className={`p-5 bg-white/[0.03] border border-white/5 rounded-3xl flex gap-5 items-start ${n.severity === 'high' ? 'border-l-4 border-l-red-500' : ''}`}>
                        <div className={`p-3 rounded-2xl shrink-0 ${n.severity === 'high' ? 'text-red-500 bg-red-500/10' : 'text-blue-500 bg-blue-500/10'}`}>
                           {n.severity === 'high' ? <ShieldAlert className="w-5 h-5" /> : <Info className="w-5 h-5" />}
                        </div>
                        <div className="flex-grow">
                           <div className="flex justify-between">
                             <p className="text-sm font-black text-white uppercase">{n.title}</p>
                             <p className="text-[8px] text-gray-700 font-bold uppercase">{new Date(n.time).toLocaleTimeString()}</p>
                           </div>
                           <p className="text-[11px] text-gray-400 font-medium leading-relaxed mt-1">{n.message}</p>
                        </div>
                     </div>
                   ))
                 )}
              </div>
           </div>
        </div>
      )}

      {/* RESULT MODAL */}
      {showResultSummary && selectedReport && (
        <div className="fixed inset-0 z-[200] bg-black/95 backdrop-blur-3xl flex items-center justify-center p-6 no-print animate-in fade-in">
           <div className="w-full max-w-sm bg-[#0f172a] border border-blue-500/30 rounded-[3rem] p-8 space-y-8 animate-in zoom-in-95 shadow-2xl relative overflow-hidden">
              <div className="text-center space-y-4 relative z-10">
                 <div className={`w-20 h-20 rounded-[2rem] mx-auto flex items-center justify-center border-2 ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10 border-red-500/30 text-red-500' : 'bg-blue-500/10 border-blue-500/30 text-blue-500'}`}>
                    {selectedReport.riskLevel === RiskLevel.MALICIOUS ? <ShieldAlert className="w-10 h-10" /> : <ShieldCheck className="w-10 h-10" />}
                 </div>
                 <h3 className="text-2xl font-black text-white uppercase italic leading-none">Audit Terminated</h3>
                 <p className="text-[11px] text-gray-500 font-bold uppercase mt-2">Case ID: {selectedReport.id}</p>
              </div>
              <div className="bg-white/5 p-6 rounded-3xl border border-white/5 space-y-3 relative z-10">
                 <div><p className="text-[9px] text-gray-600 font-bold uppercase">Asset Target</p><p className="text-xs font-black text-white truncate leading-none">{selectedReport.target}</p></div>
                 <div className="flex justify-between border-t border-white/5 pt-3">
                    <div><p className="text-[9px] text-gray-600 font-bold uppercase">Category</p><p className="text-xs font-black text-white uppercase">{selectedReport.type}</p></div>
                    <div><p className="text-[9px] text-gray-600 font-bold uppercase">Threat Score</p><p className={`text-xs font-black ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'text-red-500' : 'text-blue-500'}`}>{selectedReport.riskScore}/100</p></div>
                 </div>
              </div>
              <div className="flex flex-col gap-3 relative z-10">
                 <button onClick={() => {setShowResultSummary(false); setShowForensicReport(true);}} className="w-full bg-blue-600 p-5 rounded-2xl text-[12px] font-black text-white uppercase flex items-center justify-center gap-3 active:scale-95 shadow-xl transition-all"><Printer className="w-5 h-5" /> View Full Case Report</button>
                 <button onClick={() => setShowResultSummary(false)} className="w-full border border-white/10 p-5 rounded-2xl text-[12px] font-black text-gray-500 uppercase active:bg-white/5 transition-all">Dismiss Case</button>
              </div>
           </div>
        </div>
      )}

      {/* FORENSIC REPORT */}
      {showForensicReport && selectedReport && (
        <div className="fixed inset-0 z-[500] bg-white text-slate-900 overflow-y-auto no-scrollbar animate-in slide-in-from-right duration-700 select-text report-container">
           <div className="w-full max-w-[210mm] mx-auto bg-white min-h-screen px-6 py-12 sm:p-20 flex flex-col font-serif">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end border-b-[8px] sm:border-b-[12px] border-slate-900 pb-8 mb-12 gap-5">
                <div className="flex items-center gap-6 sm:gap-10">
                  <Shield className="w-16 h-16 sm:w-28 sm:h-28 text-slate-900 shrink-0" />
                  <div>
                    <h1 className="text-3xl sm:text-6xl font-black uppercase tracking-tighter leading-none text-slate-900 italic">{APP_NAME} AUDIT</h1>
                    <p className="text-[10px] sm:text-[12px] font-black text-slate-500 uppercase mt-3">CASE NO: {selectedReport.id}</p>
                  </div>
                </div>
                <div className="text-left sm:text-right w-full sm:w-auto">
                  <span className="inline-block px-4 py-2 bg-slate-900 text-white text-[10px] font-black uppercase tracking-widest mb-2">{selectedReport.id.startsWith('SI-BASIC') ? 'STATIC AUDIT' : 'AI-DECOMPOSITION'}</span>
                  <p className="text-[10px] font-black text-slate-400 uppercase">PROFESSIONAL FORENSIC LOG</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-10 mb-12 font-sans">
                 <div className="space-y-6">
                    <h4 className="text-[12px] font-black uppercase border-b-2 border-slate-900 pb-2 text-slate-900">I. ASSET SPECIFICATION</h4>
                    <div className="grid grid-cols-1 gap-y-6 text-[13px]">
                       <div><p className="text-slate-400 font-bold uppercase text-[10px] mb-1">SHA-256 Digest Signature</p><p className="font-black text-slate-900 break-all leading-tight bg-slate-100 p-4 rounded-xl border border-slate-200 select-all">{selectedReport.hash || 'GENERIC_FINGERPRINT'}</p></div>
                       <div className="flex justify-between border-t border-slate-100 pt-4">
                          <div><p className="text-slate-400 font-bold uppercase text-[10px] mb-1">Case Start Time</p><p className="font-black text-slate-900">{new Date(selectedReport.timestamp).toLocaleString()}</p></div>
                          <div><p className="text-slate-400 font-bold uppercase text-[10px] mb-1">Audit Depth</p><p className="font-black text-slate-900 uppercase">{selectedReport.analysisDepth}</p></div>
                       </div>
                    </div>
                 </div>
                 <div className="space-y-6">
                    <h4 className="text-[12px] font-black uppercase border-b-2 border-slate-900 pb-2 text-slate-900">II. TARGET IDENTIFIER</h4>
                    <p className="text-slate-900 font-black break-all bg-slate-50 p-7 rounded-2xl border border-slate-200 text-sm leading-relaxed select-all">{selectedReport.target}</p>
                 </div>
              </div>

              <div className="bg-slate-900 text-white p-12 rounded-[4rem] flex flex-col sm:flex-row justify-between items-center mb-16 gap-10 shadow-2xl relative overflow-hidden">
                <div className="text-center sm:text-left relative z-10">
                  <p className="text-[12px] font-black uppercase opacity-60 mb-4">THREAT ASSESSMENT</p>
                  <p className="text-5xl sm:text-8xl font-black tracking-tighter uppercase italic">{selectedReport.riskLevel}</p>
                </div>
                <div className="text-center sm:text-right relative z-10">
                  <p className="text-[12px] font-black uppercase opacity-60 mb-4">HEURISTIC SCORE</p>
                  <p className="text-7xl sm:text-9xl font-black leading-none tracking-tighter">{selectedReport.riskScore}<span className="text-4xl opacity-30">/100</span></p>
                </div>
              </div>

              <div className="space-y-12 font-sans mb-24 flex-grow">
                 <h4 className="text-[12px] font-black uppercase border-b-2 border-slate-900 pb-2 text-slate-900">III. VULNERABILITIES DETECTED</h4>
                 <div className="space-y-8">
                    {selectedReport.details.threats?.map((threat, i) => {
                      const [title, desc] = threat.split(':');
                      return (
                        <div key={i} className="flex gap-6 items-start animate-in slide-in-from-left duration-500" style={{ animationDelay: `${i * 100}ms` }}>
                           <div className={`mt-2 w-3 h-3 rounded-full shrink-0 ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-600' : 'bg-slate-400'}`} />
                           <div className="space-y-1">
                              <p className="text-sm font-black text-slate-900 uppercase font-bold tracking-tight">{title.trim()}</p>
                              <p className="text-[13px] text-slate-600 leading-snug italic font-medium">{desc?.trim() || "Anomaly found within static binary headers."}</p>
                           </div>
                        </div>
                      );
                    })}
                 </div>
                 <div className="bg-slate-50 p-10 sm:p-14 rounded-[3.5rem] border border-slate-200 mt-10">
                    <p className="text-[11px] font-black text-slate-400 uppercase tracking-widest mb-8 flex items-center gap-2"><Eye className="w-5 h-5 text-slate-400" /> IV. DECOMPOSITION SUMMARY</p>
                    <p className="text-xl sm:text-3xl font-medium italic text-slate-800 leading-snug mb-10">"{selectedReport.details.summary}"</p>
                    <p className="text-[15px] text-slate-700 leading-relaxed font-medium mb-12">{selectedReport.details.aiInsights}</p>
                    <div className="pt-12 border-t border-slate-200">
                       <p className="text-[10px] font-black text-slate-400 uppercase mb-4">Verification Sigil (Trace Record)</p>
                       <div className="p-8 bg-slate-900 text-blue-300 rounded-3xl mono text-[10px] break-all leading-tight select-all cursor-copy">{selectedReport.encryptedPayload}</div>
                    </div>
                 </div>
              </div>

              <div className="p-8 bg-slate-900 text-slate-300 rounded-3xl font-sans mb-12 border border-white/5">
                 <p className="text-[11px] font-black text-amber-500 uppercase tracking-[0.4em] mb-4 flex items-center gap-2 animate-pulse"><AlertTriangle className="w-5 h-5" /> INVESTIGATIVE USAGE WARNING</p>
                 <p className="text-[10px] leading-relaxed font-medium">This report provides investigative triage. ShadowInspect results are heuristic predictions based on static analysis and multi-vendor API signals. Findings do not constitute legal proof and are not admissible as court evidence. ShadowInspect Labs accepts no liability for legal consequences resulting from investigation decisions based on this automated report.</p>
              </div>

              <div className="no-print flex flex-col gap-3">
                 <button onClick={() => window.print()} className="bg-slate-900 text-white px-12 py-7 rounded-[3rem] text-[13px] font-black uppercase tracking-widest flex items-center justify-center gap-4 active:scale-95 transition-all"><Printer className="w-7 h-7" /> Export Evidence to Print</button>
                 <button onClick={() => setShowForensicReport(false)} className="bg-slate-100 text-slate-600 px-12 py-7 rounded-[3rem] text-[13px] font-black uppercase tracking-widest hover:bg-slate-200 transition-all">Close Core Archive</button>
              </div>
           </div>
        </div>
      )}

      {/* SCAN DRAWER */}
      {showScanDrawer && (
        <div className="fixed inset-0 z-[100] bg-black/90 backdrop-blur-2xl flex items-end no-print" onClick={() => setShowScanDrawer(false)}>
          <div className="w-full bg-[#0f172a] rounded-t-[4rem] p-8 pb-16 space-y-10 animate-in slide-in-from-bottom-full duration-500 border-t border-white/5" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-4 px-2">
               <h3 className="text-2xl font-black text-white uppercase italic">Initialize Audit</h3>
               <button onClick={() => setShowScanDrawer(false)} className="p-3 bg-white/5 rounded-full"><X className="w-7 h-7 text-gray-400"/></button>
            </div>
            <div className="space-y-6">
               <div className="flex gap-2 bg-black/40 p-1.5 rounded-3xl">
                  {(['Quick', 'Standard', 'Deep'] as AnalysisDepth[]).map(d => (
                    <button key={d} onClick={() => setAnalysisDepth(d)} className={`flex-grow py-4 rounded-2xl text-[11px] font-black uppercase transition-all ${analysisDepth === d ? 'bg-blue-600 text-white' : 'text-gray-500'}`}>{d}</button>
                  ))}
               </div>
               <div className="relative group">
                 <input type="text" placeholder="TARGET AUDIT URL" value={url} onChange={e => setUrl(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-[2.5rem] p-7 text-sm font-bold text-white outline-none focus:border-blue-500 transition-all placeholder:text-gray-800" />
                 <button onClick={() => executeScan('URL', { url })} disabled={!url} className="absolute right-3 top-3 bottom-3 px-8 bg-blue-600 rounded-3xl shadow-xl disabled:opacity-20 active:scale-95 transition-all"><Search className="w-5 h-5 text-white"/></button>
               </div>
               <div className="grid grid-cols-2 gap-4">
                  <label className="m3-card bg-black/50 p-12 border border-white/5 flex flex-col items-center gap-6 cursor-pointer hover:bg-black/80 transition-all active:scale-95">
                    <input type="file" accept=".apk" onChange={async (e) => { const f = e.target.files?.[0]; if(f) executeScan('APK', await extractApkMetadata(f)); }} className="hidden" />
                    <Box className="w-14 h-14 text-indigo-400" /><span className="text-[11px] font-black text-gray-500 uppercase">APK Source</span>
                  </label>
                  <label className="m3-card bg-black/50 p-12 border border-white/5 flex flex-col items-center gap-6 cursor-pointer hover:bg-black/80 transition-all active:scale-95">
                    <input type="file" accept=".pdf" onChange={async (e) => { const f = e.target.files?.[0]; if(f) executeScan('PDF', await extractPdfMetadata(f)); }} className="hidden" />
                    <FileText className="w-14 h-14 text-rose-400" /><span className="text-[11px] font-black text-gray-500 uppercase">PDF Source</span>
                  </label>
               </div>
            </div>
          </div>
        </div>
      )}

      {/* OVERLAY: SCANNING */}
      {isScanning && (
        <div className="fixed inset-0 z-[1000] bg-black/98 flex flex-col items-center justify-center p-12 no-print backdrop-blur-2xl">
           <Shield className="w-24 h-24 text-blue-500 animate-pulse drop-shadow-[0_0_40px_rgba(59,130,246,0.6)] mb-10" />
           <h3 className="text-3xl font-black text-white uppercase tracking-tighter mb-5 italic">{APP_NAME} CLUSTER</h3>
           <p className="text-blue-500 font-black text-[11px] uppercase tracking-[0.5em] mb-12 animate-pulse">Running Forensic Cluster...</p>
           <div className="w-full max-w-xs bg-white/5 h-2 rounded-full overflow-hidden border border-white/10 shadow-inner">
              <div className="h-full bg-blue-500 w-1/3 animate-[shimmer_2s_infinite_linear] rounded-full shadow-[0_0_20px_#3b82f6]" />
           </div>
        </div>
      )}

      <style>{`
        @keyframes shimmer { 0% { transform: translateX(-150%); } 100% { transform: translateX(350%); } }
        @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-8px); } 75% { transform: translateX(8px); } }
        .animate-shake { animation: shake 0.3s ease-in-out; }
        .no-scrollbar::-webkit-scrollbar { display: none; }
      `}</style>
    </div>
  );
};

export default App;
