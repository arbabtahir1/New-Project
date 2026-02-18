
import React, { useState, useEffect } from 'react';
import { 
  Shield, Search, History as HistoryIcon, FileSearch, Globe, 
  AlertTriangle, CheckCircle2, ShieldAlert, X, Plus, Clock, 
  ChevronRight, FileText, Fingerprint, Activity, Info, Lock, 
  Cpu, ShieldCheck, Zap, LayoutGrid, Settings, QrCode, MapPin, 
  MoreVertical, ArrowLeft, Database, Trash2, Share2, HardDrive, 
  RefreshCw, Terminal, Download, Printer, ExternalLink
} from 'lucide-react';
import { AnalysisReport, RiskLevel } from './types';
import { extractApkMetadata, extractPdfMetadata, isValidUrl } from './utils/security';
import { analyzeSecurityThreat } from './services/geminiService';

const APP_VERSION = "3.2.0-FORENSIC-PRO";

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'home' | 'history' | 'labs'>('home');
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [history, setHistory] = useState<AnalysisReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null);
  const [showForensicReport, setShowForensicReport] = useState(false);
  const [showScanDrawer, setShowScanDrawer] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  
  useEffect(() => {
    const saved = localStorage.getItem('sandbox_history');
    if (saved) setHistory(JSON.parse(saved));
  }, []);

  const saveReport = (report: AnalysisReport) => {
    const newHistory = [report, ...history].slice(0, 50);
    setHistory(newHistory);
    localStorage.setItem('sandbox_history', JSON.stringify(newHistory));
    setSelectedReport(report);
    setShowScanDrawer(false);
  };

  const clearHistory = () => {
    if (window.confirm("CRITICAL: Purge all forensic records? This cannot be undone.")) {
      setHistory([]);
      localStorage.removeItem('sandbox_history');
      setShowSettings(false);
    }
  };

  const handleUrlScan = async () => {
    if (!isValidUrl(url)) {
      alert("Invalid Asset URL");
      return;
    }
    setIsScanning(true);
    try {
      const aiResult = await analyzeSecurityThreat('URL', { url });
      const riskLevel = aiResult.riskScore > 75 ? RiskLevel.MALICIOUS : aiResult.riskScore > 30 ? RiskLevel.SUSPICIOUS : RiskLevel.SAFE;
      const report: AnalysisReport = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        type: 'URL',
        target: url,
        riskScore: aiResult.riskScore,
        riskLevel,
        details: { 
          summary: aiResult.summary, 
          aiInsights: aiResult.insights 
        }
      };
      saveReport(report);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
      setUrl('');
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsScanning(true);
    setShowScanDrawer(false);
    try {
      const isApk = file.name.endsWith('.apk');
      const metadata = isApk ? await extractApkMetadata(file) : await extractPdfMetadata(file);
      const aiResult = await analyzeSecurityThreat(isApk ? 'APK' : 'PDF', isApk ? metadata : { ...metadata, filename: file.name });
      const riskLevel = aiResult.riskScore > 75 ? RiskLevel.MALICIOUS : aiResult.riskScore > 30 ? RiskLevel.SUSPICIOUS : RiskLevel.SAFE;
      const report: AnalysisReport = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        type: isApk ? 'APK' : 'PDF',
        target: file.name,
        hash: metadata.hash,
        riskScore: aiResult.riskScore,
        riskLevel,
        details: {
          packageName: (metadata as any).packageName,
          permissions: (metadata as any).permissions,
          pdfMetadata: (metadata as any).pdfMetadata,
          summary: aiResult.summary,
          aiInsights: aiResult.insights
        }
      };
      saveReport(report);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  const handlePrint = () => window.print();

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#0a0c10]">
      <div className="h-10 shrink-0" /> {/* System status bar spacing */}

      <div className="flex-grow overflow-y-auto pb-24 px-4 scroll-smooth">
        {/* Navigation Header */}
        {!selectedReport || activeTab !== 'home' ? (
          <div className="pt-4 pb-8 flex justify-between items-center animate-in fade-in slide-in-from-top-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                <p className="text-[10px] font-black text-blue-500 uppercase tracking-[0.3em]">Sector 01 Alpha</p>
              </div>
              <h1 className="text-3xl font-black text-white tracking-tighter">Sandbox Pro</h1>
            </div>
            <button 
              onClick={() => setShowSettings(true)} 
              className="p-3 bg-white/5 rounded-2xl active:rotate-90 transition-all duration-500 border border-white/5"
            >
              <Settings className="w-6 h-6 text-gray-400" />
            </button>
          </div>
        ) : (
          <div className="pt-4 pb-4 flex items-center gap-4 sticky top-0 bg-[#0a0c10]/95 backdrop-blur-md z-20">
            <button onClick={() => setSelectedReport(null)} className="p-3 bg-white/5 rounded-2xl active:scale-90 transition-transform">
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex-grow">
              <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest leading-none mb-1">Audit Record</p>
              <h2 className="text-lg font-black text-white truncate w-48 uppercase tracking-tight">{selectedReport.type} Analysis</h2>
            </div>
            <button onClick={() => setShowForensicReport(true)} className="p-3 bg-blue-600 rounded-2xl active:scale-95 shadow-lg shadow-blue-600/20">
              <Fingerprint className="w-5 h-5 text-white" />
            </button>
          </div>
        )}

        {/* Tab Content: HOME */}
        {activeTab === 'home' && (
          <div className="space-y-6 animate-in slide-in-from-bottom-6 duration-500">
            {selectedReport ? (
              <div className="space-y-6">
                {/* Score Hero */}
                <div className={`m3-card p-6 border border-white/5 ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10' : 'bg-blue-500/10'}`}>
                  <div className="flex justify-between items-start mb-6">
                    <div className="p-4 bg-black/40 rounded-3xl">
                      {selectedReport.riskLevel === RiskLevel.MALICIOUS ? <ShieldAlert className="w-8 h-8 text-red-500" /> : <ShieldCheck className="w-8 h-8 text-blue-400" />}
                    </div>
                    <div className="text-right">
                      <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-1">Risk Heuristics</p>
                      <p className={`text-4xl font-black ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'text-red-500' : 'text-blue-400'}`}>
                        {selectedReport.riskScore}<span className="text-lg opacity-30">/100</span>
                      </p>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="bg-black/20 p-4 rounded-2xl">
                      <p className="text-[10px] text-gray-500 font-bold uppercase mb-1">Asset Hash (SHA-256)</p>
                      <p className="text-[11px] font-mono break-all text-blue-300 opacity-80">{selectedReport.hash || 'DYNAMIC_ASSET_NO_HASH'}</p>
                    </div>
                    <div className="bg-black/20 p-4 rounded-2xl">
                      <p className="text-[10px] text-gray-500 font-bold uppercase mb-1">Target Identity</p>
                      <p className="text-sm font-black text-white truncate uppercase">{selectedReport.target}</p>
                    </div>
                  </div>
                </div>

                {/* AI Findings */}
                <div className="m3-card p-6 border border-white/5 space-y-4">
                  <h3 className="text-xs font-black text-blue-500 uppercase tracking-widest flex items-center gap-2"><Zap className="w-4 h-4 fill-blue-500"/> AI AUDIT LOG</h3>
                  <div className="relative">
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-blue-500 to-transparent rounded-full opacity-30" />
                    <p className="text-sm italic text-gray-200 leading-relaxed pl-5 font-medium">{selectedReport.details.summary}</p>
                  </div>
                  <div className="bg-[#121212] p-4 rounded-2xl border border-white/5">
                    <p className="text-[9px] font-black text-gray-500 uppercase tracking-widest mb-2">Technical Insight</p>
                    <p className="text-xs text-gray-400 leading-relaxed">{selectedReport.details.aiInsights}</p>
                  </div>
                </div>

                {/* Specifics (Permissions/Metadata) */}
                {selectedReport.details.permissions && (
                  <div className="m3-card p-6 border border-white/5">
                    <h3 className="text-xs font-black text-gray-400 uppercase tracking-widest mb-4">Permission Audit</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedReport.details.permissions.map(p => (
                        <div key={p} className="px-3 py-1.5 bg-red-500/10 border border-red-500/10 rounded-lg text-[9px] font-bold text-red-400 uppercase tracking-tight">
                          {p.split('.').pop()}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <>
                {/* Main Banner */}
                <div 
                  className="m3-card p-8 bg-gradient-to-br from-blue-700 to-indigo-950 shadow-2xl relative overflow-hidden active:scale-[0.98] transition-transform"
                  onClick={() => setShowScanDrawer(true)}
                >
                  <div className="absolute top-[-20%] right-[-10%] opacity-10">
                    <Shield className="w-48 h-48" />
                  </div>
                  <div className="relative z-10">
                    <div className="p-3 bg-white/10 w-fit rounded-2xl mb-6">
                      <Plus className="w-8 h-8 text-white" />
                    </div>
                    <h2 className="text-3xl font-black text-white leading-tight mb-2 tracking-tighter">Start Forensic<br/>Asset Audit</h2>
                    <p className="text-blue-200/60 text-xs font-bold uppercase tracking-[0.2em]">Static & Heuristic Analysis</p>
                  </div>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="m3-card p-6 border border-white/5 bg-[#1c1b1f]">
                    <Activity className="w-6 h-6 text-green-400 mb-4" />
                    <p className="text-2xl font-black text-white">{history.length}</p>
                    <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Case Records</p>
                  </div>
                  <div className="m3-card p-6 border border-white/5 bg-[#1c1b1f]">
                    <Cpu className="w-6 h-6 text-purple-400 mb-4" />
                    <p className="text-2xl font-black text-white">3.2.0</p>
                    <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Engine Core</p>
                  </div>
                </div>

                {/* System Health */}
                <div className="space-y-3">
                  <h3 className="px-2 text-[10px] font-black text-gray-500 uppercase tracking-widest">Lab Services</h3>
                  <div className="m3-card p-5 flex items-center gap-4 bg-[#1c1b1f] border border-white/5">
                    <div className="p-3 bg-blue-500/10 rounded-2xl"><Terminal className="w-5 h-5 text-blue-400" /></div>
                    <div className="flex-grow">
                      <p className="text-xs font-black text-white uppercase">Heuristic Engine</p>
                      <p className="text-[9px] text-gray-500 font-bold uppercase">Gemini-3 Pro Connected</p>
                    </div>
                    <div className="w-2 h-2 rounded-full bg-green-500" />
                  </div>
                  <div className="m3-card p-5 flex items-center gap-4 bg-[#1c1b1f] border border-white/5">
                    <div className="p-3 bg-amber-500/10 rounded-2xl"><Lock className="w-5 h-5 text-amber-400" /></div>
                    <div className="flex-grow">
                      <p className="text-xs font-black text-white uppercase">Archive Vault</p>
                      <p className="text-[9px] text-gray-500 font-bold uppercase">Local Encrypted Store</p>
                    </div>
                    <div className="w-2 h-2 rounded-full bg-green-500" />
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* Tab Content: HISTORY */}
        {activeTab === 'history' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="px-2 flex justify-between items-center">
              <h2 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em]">Audit Archive</h2>
              <p className="text-[10px] font-black text-blue-500 uppercase">{history.length} Entries</p>
            </div>
            <div className="space-y-4">
              {history.map(item => (
                <div 
                  key={item.id} 
                  onClick={() => {setSelectedReport(item); setActiveTab('home');}} 
                  className="m3-card p-4 bg-white/5 border border-white/5 flex items-center justify-between active:scale-[0.98] transition-transform"
                >
                  <div className="flex items-center gap-4 max-w-[80%]">
                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center ${item.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10 text-red-500' : 'bg-blue-500/10 text-blue-400'}`}>
                      {item.type === 'URL' ? <Globe className="w-6 h-6"/> : item.type === 'APK' ? <FileSearch className="w-6 h-6"/> : <FileText className="w-6 h-6"/>}
                    </div>
                    <div className="overflow-hidden">
                      <p className="text-sm font-black text-white truncate uppercase tracking-tight">{item.target}</p>
                      <p className="text-[9px] text-gray-500 font-bold uppercase mt-1 flex items-center gap-2">
                        <Clock className="w-3 h-3" /> {new Date(item.timestamp).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className={`text-sm font-black ${item.riskLevel === RiskLevel.MALICIOUS ? 'text-red-500' : 'text-blue-500'}`}>
                    {item.riskScore}
                  </div>
                </div>
              ))}
              {history.length === 0 && (
                <div className="py-24 text-center opacity-20 flex flex-col items-center gap-4">
                  <Database className="w-16 h-16" />
                  <p className="text-xs font-black uppercase tracking-widest">No Forensic Records Found</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab Content: LABS */}
        {activeTab === 'labs' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <h2 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em] px-2">Experimental Units</h2>
            
            <div className="m3-card p-6 bg-white/5 border border-white/5 space-y-4">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-purple-500/10 rounded-2xl"><RefreshCw className="w-6 h-6 text-purple-400" /></div>
                <div>
                  <h3 className="text-sm font-black text-white uppercase">Binary Decompiler</h3>
                  <p className="text-[9px] text-purple-500 font-bold uppercase">DEX to Kotlin v2</p>
                </div>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">Simulated structural analysis for identifying code-level obfuscation and malicious reflection patterns.</p>
              <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                <div className="h-full bg-purple-500 w-[45%] animate-pulse" />
              </div>
              <p className="text-[9px] font-black text-center text-gray-600 uppercase tracking-widest">Internal Alpha Testing Only</p>
            </div>

            <div className="m3-card p-6 bg-white/5 border border-white/5 space-y-4">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-emerald-500/10 rounded-2xl"><Globe className="w-6 h-6 text-emerald-400" /></div>
                <div>
                  <h3 className="text-sm font-black text-white uppercase">Network Intercept</h3>
                  <p className="text-[9px] text-emerald-500 font-bold uppercase">TLS Handshake Audit</p>
                </div>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">Packet-level monitoring for unauthorized API calls and command-and-control communication.</p>
              <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                <div className="h-full bg-emerald-500 w-[80%] animate-pulse" />
              </div>
              <p className="text-[9px] font-black text-center text-gray-600 uppercase tracking-widest">Sector Deployed: Cluster 01</p>
            </div>
          </div>
        )}
      </div>

      {/* Global Modals & Drawers */}

      {/* SCAN DRAWER */}
      {showScanDrawer && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md flex items-end animate-in fade-in duration-300">
          <div className="w-full bg-[#1c1b1f] rounded-t-[40px] p-8 pb-16 space-y-8 animate-in slide-in-from-bottom-full duration-500">
            <div className="flex justify-between items-center">
              <h3 className="text-2xl font-black text-white uppercase tracking-tighter">Initialize Audit</h3>
              <button onClick={() => setShowScanDrawer(false)} className="p-3 bg-white/5 rounded-full active:scale-90"><X className="w-6 h-6" /></button>
            </div>
            
            <div className="space-y-6">
              <div className="relative group">
                <input 
                  type="text" 
                  placeholder="INPUT TARGET URL" 
                  value={url} 
                  onChange={e => setUrl(e.target.value)} 
                  className="w-full bg-black/40 border border-white/10 rounded-3xl p-6 pr-20 text-sm font-black uppercase tracking-widest text-white outline-none focus:border-blue-500 transition-all placeholder:text-gray-700" 
                />
                <button 
                  onClick={handleUrlScan} 
                  disabled={!url || isScanning} 
                  className="absolute right-3 top-3 bottom-3 px-6 bg-blue-600 rounded-2xl shadow-xl active:scale-95 disabled:opacity-20 transition-all"
                >
                  {isScanning ? <RefreshCw className="w-5 h-5 animate-spin text-white" /> : <Search className="w-5 h-5 text-white" />}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <label className="m3-card bg-white/5 p-8 border border-white/5 flex flex-col items-center gap-4 cursor-pointer active:scale-95 transition-transform hover:bg-white/10">
                  <input type="file" accept=".apk" onChange={handleFileUpload} className="hidden" />
                  <div className="p-4 bg-indigo-500/20 rounded-2xl"><FileSearch className="w-8 h-8 text-indigo-400" /></div>
                  <span className="text-[10px] font-black text-gray-400 uppercase tracking-widest">DEEP APK</span>
                </label>
                <label className="m3-card bg-white/5 p-8 border border-white/5 flex flex-col items-center gap-4 cursor-pointer active:scale-95 transition-transform hover:bg-white/10">
                  <input type="file" accept=".pdf" onChange={handleFileUpload} className="hidden" />
                  <div className="p-4 bg-rose-500/20 rounded-2xl"><FileText className="w-8 h-8 text-rose-400" /></div>
                  <span className="text-[10px] font-black text-gray-400 uppercase tracking-widest">SECURE PDF</span>
                </label>
              </div>
            </div>

            <div className="bg-blue-600/10 p-4 rounded-2xl border border-blue-600/10 text-center">
              <p className="text-[10px] text-blue-400 font-bold uppercase tracking-tight italic">
                Scanning engine supports static decomposition & AI heuristic analysis.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* FORENSIC REPORT VIEW */}
      {showForensicReport && selectedReport && (
        <div className="fixed inset-0 z-[100] bg-black p-0 overflow-y-auto no-scrollbar animate-in zoom-in-95 duration-300">
          <div className="min-h-screen bg-white text-slate-900 p-10 font-serif print:p-0">
             <div className="max-w-4xl mx-auto space-y-12">
                {/* PDF Header */}
                <div className="flex justify-between items-end border-b-[8px] border-slate-900 pb-8">
                   <div className="space-y-2">
                      <div className="flex items-center gap-3">
                         <Shield className="w-10 h-10 text-slate-900" />
                         <h1 className="text-4xl font-black uppercase tracking-tighter text-slate-900 leading-none">FORENSIC CASE LOG</h1>
                      </div>
                      <p className="text-[11px] font-black text-slate-400 uppercase tracking-[0.3em]">MOBILE SECURITY LABS • ARTIFACT AUDIT v{APP_VERSION}</p>
                   </div>
                   <div className="text-right">
                      <p className="text-[10px] font-black text-slate-400 uppercase mb-1">Audit Status</p>
                      <p className={`text-xl font-black ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'text-red-600' : 'text-slate-900'}`}>
                        {selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'CERTIFIED_THREAT' : 'AUDITED_ASSET'}
                      </p>
                   </div>
                </div>

                <div className="grid grid-cols-2 gap-16 font-sans">
                   <div className="space-y-6">
                      <h4 className="text-[11px] font-black uppercase border-b-2 border-slate-200 pb-2 tracking-widest">Case Metadata</h4>
                      <div className="grid grid-cols-2 gap-y-4 text-[11px]">
                         <span className="text-slate-400 font-bold uppercase">Asset Category:</span><span className="font-black truncate">{selectedReport.type}</span>
                         <span className="text-slate-400 font-bold uppercase">Source Path:</span><span className="font-black truncate">{selectedReport.target}</span>
                         <span className="text-slate-400 font-bold uppercase">Log Timestamp:</span><span className="font-black truncate">{new Date(selectedReport.timestamp).toLocaleString()}</span>
                         <span className="text-slate-400 font-bold uppercase">Registry ID:</span><span className="font-mono text-[9px]">{selectedReport.id.substring(0,18)}</span>
                      </div>
                   </div>
                   <div className="space-y-6">
                      <h4 className="text-[11px] font-black uppercase border-b-2 border-slate-200 pb-2 tracking-widest">Integrity Signature</h4>
                      <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 mono text-[10px] break-all leading-relaxed shadow-sm">
                         {selectedReport.hash || 'DYNAMIC_STREAM_AUDIT_NO_STATIC_HASH'}
                      </div>
                   </div>
                </div>

                <div className="bg-slate-900 text-white p-10 rounded-[40px] flex justify-between items-center font-sans shadow-2xl">
                   <div className="space-y-2">
                      <p className="text-[11px] font-black uppercase opacity-50 tracking-[0.2em]">Risk Classification</p>
                      <p className="text-5xl font-black">{selectedReport.riskLevel}</p>
                   </div>
                   <div className="text-right space-y-2">
                      <p className="text-[11px] font-black uppercase opacity-50 tracking-[0.2em]">Heuristic Score</p>
                      <p className="text-7xl font-black leading-none">{selectedReport.riskScore}<span className="text-2xl opacity-30">/100</span></p>
                   </div>
                </div>

                <div className="space-y-6 font-sans">
                   <h4 className="text-[11px] font-black uppercase border-b-2 border-slate-200 pb-2 tracking-widest">Forensic Observations</h4>
                   <div className="relative">
                      <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-slate-300 rounded-full" />
                      <p className="text-lg font-medium italic pl-8 py-2 leading-relaxed text-slate-800">
                         "{selectedReport.details.summary}"
                      </p>
                   </div>
                   <div className="bg-slate-50 p-8 rounded-3xl text-sm leading-relaxed text-slate-700 border border-slate-200">
                      <p className="font-black uppercase text-[10px] mb-4 text-slate-400 tracking-widest">Expert AI Deep-Dive Analysis:</p>
                      {selectedReport.details.aiInsights}
                   </div>
                </div>

                <div className="pt-24 flex justify-between items-end border-t-2 border-slate-100">
                   <div className="space-y-6">
                      <div className="flex gap-12 font-sans">
                         <div className="space-y-1">
                            <p className="text-[9px] font-black text-slate-300 uppercase">Analysis Engine</p>
                            <p className="text-[10px] font-bold">MS-LAB-SANDBOX v{APP_VERSION}</p>
                         </div>
                         <div className="space-y-1">
                            <p className="text-[9px] font-black text-slate-300 uppercase">Seal Authority</p>
                            <p className="text-[10px] font-mono text-slate-400">SEC-CERT-01-ALPHA</p>
                         </div>
                      </div>
                      <p className="text-[9px] text-slate-400 max-w-sm uppercase font-bold leading-relaxed">This artifact is a legal forensic record generated via static decomposition. Unauthorized duplication of this log is prohibited under Sector 7 Security Protocol.</p>
                   </div>
                   <div className="no-print flex gap-3">
                      <button onClick={handlePrint} className="bg-slate-900 text-white px-8 py-4 rounded-2xl text-[11px] font-black uppercase tracking-widest shadow-xl active:scale-95 transition-all flex items-center gap-2">
                        <Printer className="w-4 h-4" /> Print Record
                      </button>
                      <button onClick={() => setShowForensicReport(false)} className="bg-white border-2 border-slate-200 text-slate-600 px-8 py-4 rounded-2xl text-[11px] font-black uppercase tracking-widest hover:bg-slate-50 transition-all">Close</button>
                   </div>
                </div>
             </div>
          </div>
        </div>
      )}

      {/* SETTINGS DRAWER */}
      {showSettings && (
        <div className="fixed inset-0 z-[60] bg-black/90 backdrop-blur-md flex items-end animate-in fade-in duration-300">
          <div className="w-full bg-[#1c1b1f] rounded-t-[40px] p-10 pb-16 space-y-8 animate-in slide-in-from-bottom-full duration-500">
            <div className="flex justify-between items-center">
              <h3 className="text-2xl font-black text-white uppercase tracking-tighter">Unit Settings</h3>
              <button onClick={() => setShowSettings(false)} className="p-3 bg-white/5 rounded-full"><X/></button>
            </div>
            
            <div className="space-y-4">
              <button 
                onClick={clearHistory} 
                className="w-full p-6 m3-card bg-red-500/10 border border-red-500/20 flex items-center gap-5 text-red-500 active:scale-[0.98] transition-all"
              >
                <Trash2 className="w-6 h-6" />
                <div className="text-left">
                  <p className="text-sm font-black uppercase tracking-tight">Purge All Records</p>
                  <p className="text-[10px] font-bold uppercase opacity-50">Irreversible Wipe</p>
                </div>
              </button>

              <div className="p-6 m3-card bg-white/5 border border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-5 text-gray-400">
                  <Info className="w-6 h-6" />
                  <div className="text-left">
                    <p className="text-sm font-black uppercase tracking-tight text-white">System Build</p>
                    <p className="text-[10px] font-mono text-gray-500">{APP_VERSION}</p>
                  </div>
                </div>
              </div>

              <div className="p-6 m3-card bg-white/5 border border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-5 text-gray-400">
                  <HardDrive className="w-6 h-6" />
                  <div className="text-left">
                    <p className="text-sm font-black uppercase tracking-tight text-white">Cloud Sync</p>
                    <p className="text-[10px] font-bold uppercase text-green-500">SECURE_ACTIVE</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-blue-600 p-5 rounded-3xl text-center shadow-2xl active:scale-95 transition-transform" onClick={() => setShowSettings(false)}>
              <p className="text-xs font-black text-white uppercase tracking-widest">Return to Terminal</p>
            </div>
          </div>
        </div>
      )}

      {/* BOTTOM NAVIGATION (Native Material 3 Look) */}
      <nav className="fixed bottom-0 left-0 right-0 bg-[#1c1b1f]/95 backdrop-blur-2xl border-t border-white/5 h-24 flex justify-around items-center px-6 z-40 no-print">
        <button 
          onClick={() => {setActiveTab('home'); setSelectedReport(null);}} 
          className={`flex flex-col items-center gap-2 group w-20 transition-all ${activeTab === 'home' ? 'text-blue-500' : 'text-gray-600'}`}
        >
          <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === 'home' ? 'bg-blue-600/10 scale-110' : 'group-active:bg-white/5'}`}>
            <LayoutGrid className={`w-6 h-6 ${activeTab === 'home' ? 'stroke-[2.5]' : 'stroke-[1.5]'}`} />
          </div>
          <span className="text-[9px] font-black uppercase tracking-[0.1em]">Terminal</span>
        </button>

        <button 
          onClick={() => setActiveTab('history')} 
          className={`flex flex-col items-center gap-2 group w-20 transition-all ${activeTab === 'history' ? 'text-blue-500' : 'text-gray-600'}`}
        >
          <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === 'history' ? 'bg-blue-600/10 scale-110' : 'group-active:bg-white/5'}`}>
            <HistoryIcon className={`w-6 h-6 ${activeTab === 'history' ? 'stroke-[2.5]' : 'stroke-[1.5]'}`} />
          </div>
          <span className="text-[9px] font-black uppercase tracking-[0.1em]">Archive</span>
        </button>

        <button 
          onClick={() => setActiveTab('labs')} 
          className={`flex flex-col items-center gap-2 group w-20 transition-all ${activeTab === 'labs' ? 'text-blue-500' : 'text-gray-600'}`}
        >
          <div className={`w-16 h-10 rounded-full flex items-center justify-center transition-all ${activeTab === 'labs' ? 'bg-blue-600/10 scale-110' : 'group-active:bg-white/5'}`}>
            <Cpu className={`w-6 h-6 ${activeTab === 'labs' ? 'stroke-[2.5]' : 'stroke-[1.5]'}`} />
          </div>
          <span className="text-[9px] font-black uppercase tracking-[0.1em]">Labs</span>
        </button>
      </nav>

      {/* SCANNING OVERLAY */}
      {isScanning && (
        <div className="fixed inset-0 z-[200] bg-[#0a0c10]/80 backdrop-blur-xl flex flex-col items-center justify-center text-center p-10 animate-in fade-in duration-500">
           <div className="relative mb-10">
              <Shield className="w-24 h-24 text-blue-500 animate-pulse" />
              <div className="absolute inset-0 border-4 border-blue-500/20 rounded-full animate-ping" />
           </div>
           <h3 className="text-2xl font-black text-white uppercase tracking-tighter mb-4">Decomposing Asset</h3>
           <p className="text-blue-500/60 text-xs font-black uppercase tracking-[0.3em] mb-8 animate-pulse">Running Static Heuristics...</p>
           <div className="w-full max-w-xs bg-white/5 h-1.5 rounded-full overflow-hidden">
              <div className="h-full bg-blue-500 w-1/2 animate-[shimmer_2s_infinite_linear] rounded-full" />
           </div>
           <style>{`
             @keyframes shimmer {
               0% { transform: translateX(-100%); }
               100% { transform: translateX(200%); }
             }
           `}</style>
        </div>
      )}
    </div>
  );
};

export default App;
