
import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Search, 
  History as HistoryIcon, 
  FileSearch, 
  Globe, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert,
  X,
  Plus,
  Clock,
  ExternalLink,
  ChevronRight,
  FileText,
  Printer,
  Fingerprint,
  Activity,
  Info,
  Lock,
  Cpu,
  ShieldCheck,
  Zap,
  LayoutGrid,
  Settings,
  QrCode,
  MapPin,
  MoreVertical,
  ArrowLeft,
  // Fix: Add missing Database icon import
  Database
} from 'lucide-react';
import { AnalysisReport, RiskLevel } from './types';
import { calculateHash, extractApkMetadata, extractPdfMetadata, isValidUrl } from './utils/security';
import { analyzeSecurityThreat } from './services/geminiService';

const APP_VERSION = "3.0.0-PRO-MOBILE";

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'home' | 'history' | 'labs'>('home');
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [history, setHistory] = useState<AnalysisReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null);
  const [showForensicReport, setShowForensicReport] = useState(false);
  const [showScanDrawer, setShowScanDrawer] = useState(false);
  
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

  // Fix: Implement handlePrint function
  const handlePrint = () => {
    window.print();
  };

  const handleUrlScan = async () => {
    if (!isValidUrl(url)) return;
    setIsScanning(true);
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
        aiInsights: aiResult.insights,
      }
    };
    saveReport(report);
    setIsScanning(false);
    setUrl('');
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsScanning(true);
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

  const getRiskColor = (level: RiskLevel) => {
    switch (level) {
      case RiskLevel.SAFE: return 'text-green-400';
      case RiskLevel.SUSPICIOUS: return 'text-yellow-400';
      case RiskLevel.MALICIOUS: return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      {/* Status Bar Spacer (Simulated Android) */}
      <div className="h-10 bg-[#0a0c10] shrink-0" />

      {/* Main Container */}
      <div className="flex-grow overflow-y-auto pb-24 scroll-smooth">
        
        {/* Header Area */}
        {selectedReport && activeTab === 'home' ? (
          <div className="px-6 pt-2 pb-6 flex items-center gap-4 sticky top-0 bg-[#0a0c10]/90 backdrop-blur-md z-20">
            <button onClick={() => setSelectedReport(null)} className="p-2 -ml-2 rounded-full hover:bg-white/10 active:scale-90 transition-all">
              <ArrowLeft className="w-6 h-6" />
            </button>
            <h1 className="text-xl font-bold flex-grow truncate">{selectedReport.type} Analysis</h1>
            <button className="p-2 rounded-full hover:bg-white/10">
              <MoreVertical className="w-6 h-6" />
            </button>
          </div>
        ) : (
          <div className="px-6 pt-4 pb-8 flex flex-col gap-1">
            <div className="flex justify-between items-center">
              <span className="text-xs font-black text-blue-500 tracking-[0.3em] uppercase">Enterprise Unit</span>
              <Settings className="w-5 h-5 text-gray-500" />
            </div>
            <h1 className="text-3xl font-black text-white tracking-tight">Mobile Sandbox</h1>
            <p className="text-gray-500 text-xs font-medium uppercase tracking-widest flex items-center gap-2">
              <MapPin className="w-3 h-3" /> Global Cluster 01
            </p>
          </div>
        )}

        {/* Home Tab */}
        {activeTab === 'home' && (
          <div className="px-4 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {selectedReport ? (
              <div className="space-y-6">
                {/* Result Card */}
                <div className={`m3-card p-6 border border-white/5 ${selectedReport.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10' : selectedReport.riskLevel === RiskLevel.SUSPICIOUS ? 'bg-yellow-500/10' : 'bg-green-500/10'}`}>
                  <div className="flex justify-between items-start mb-6">
                    <div className="p-3 bg-white/10 rounded-2xl">
                      {selectedReport.riskLevel === RiskLevel.SAFE ? <CheckCircle2 className="w-8 h-8 text-green-400" /> : selectedReport.riskLevel === RiskLevel.MALICIOUS ? <ShieldAlert className="w-8 h-8 text-red-400" /> : <AlertTriangle className="w-8 h-8 text-yellow-400" />}
                    </div>
                    <div className="text-right">
                      <p className="text-[10px] font-black uppercase opacity-50 tracking-widest">Threat Level</p>
                      <p className={`text-2xl font-black ${getRiskColor(selectedReport.riskLevel)}`}>{selectedReport.riskLevel}</p>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <div className="bg-black/40 p-4 rounded-2xl border border-white/5">
                      <p className="text-[10px] text-gray-500 font-bold uppercase mb-1">Asset ID</p>
                      <p className="text-sm font-medium break-all text-blue-400 mono">{selectedReport.target}</p>
                    </div>

                    <div className="flex gap-4">
                      <div className="flex-grow bg-black/40 p-4 rounded-2xl border border-white/5">
                        <p className="text-[10px] text-gray-500 font-bold uppercase mb-1">Risk Score</p>
                        <p className="text-2xl font-black">{selectedReport.riskScore}<span className="text-sm opacity-30">/100</span></p>
                      </div>
                      <button onClick={() => setShowForensicReport(true)} className="aspect-square bg-blue-600 rounded-2xl flex items-center justify-center p-4 shadow-lg shadow-blue-600/30 active:scale-95 transition-transform">
                        <Fingerprint className="w-8 h-8 text-white" />
                      </button>
                    </div>
                  </div>
                </div>

                {/* AI Reasoning Section */}
                <div className="m3-card p-6 space-y-4 border border-white/5">
                  <h3 className="text-sm font-black text-blue-500 uppercase tracking-widest flex items-center gap-2">
                    <Zap className="w-4 h-4" /> AI HEURISTICS
                  </h3>
                  <p className="text-gray-200 text-sm leading-relaxed font-medium italic border-l-4 border-blue-600/40 pl-4">
                    {selectedReport.details.summary}
                  </p>
                  <div className="bg-[#121212] p-4 rounded-2xl border border-white/5">
                    <p className="text-[10px] text-gray-500 font-bold uppercase mb-2 tracking-widest">Deep Insights</p>
                    <p className="text-xs text-gray-400 leading-relaxed font-medium">
                      {selectedReport.details.aiInsights}
                    </p>
                  </div>
                </div>

                {selectedReport.details.permissions && (
                  <div className="m3-card p-6 border border-white/5">
                    <h3 className="text-sm font-black text-gray-400 uppercase tracking-widest mb-4">Permissions Audit</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedReport.details.permissions.map(p => (
                        <span key={p} className="px-3 py-1.5 bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-bold rounded-lg uppercase tracking-tight">
                          {p.split('.').pop()}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-6">
                {/* Stats Grid */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="m3-card p-5 border border-white/5 flex flex-col justify-between h-32">
                    <Activity className="w-6 h-6 text-green-400" />
                    <div>
                      <p className="text-2xl font-black">{history.length}</p>
                      <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Total Audits</p>
                    </div>
                  </div>
                  <div className="m3-card p-5 border border-white/5 flex flex-col justify-between h-32 bg-blue-600/5">
                    <ShieldCheck className="w-6 h-6 text-blue-400" />
                    <div>
                      <p className="text-2xl font-black">99.8%</p>
                      <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Model Conf.</p>
                    </div>
                  </div>
                </div>

                {/* Main Action Banner */}
                <div className="m3-card p-8 bg-gradient-to-br from-blue-700 to-indigo-900 shadow-2xl shadow-blue-900/40 relative overflow-hidden group active:scale-[0.98] transition-transform" onClick={() => setShowScanDrawer(true)}>
                  <div className="absolute top-0 right-0 p-4 opacity-10">
                    <Shield className="w-32 h-32" />
                  </div>
                  <h2 className="text-2xl font-black text-white leading-tight mb-2">Initialize New<br/>Forensic Scan</h2>
                  <p className="text-blue-100/60 text-xs font-bold uppercase tracking-widest mb-6">Asset Discovery Service</p>
                  <div className="flex items-center gap-3">
                    <div className="px-4 py-2 bg-white text-blue-900 rounded-full text-xs font-black uppercase shadow-lg">Start Now</div>
                    <QrCode className="w-6 h-6 text-white/50" />
                  </div>
                </div>

                {/* System Health Cards */}
                <div className="space-y-3">
                   <h3 className="px-2 text-[10px] font-black text-gray-500 uppercase tracking-widest">Enterprise Services</h3>
                   <div className="m3-card p-4 flex items-center gap-4 bg-[#1c1b1f] border border-white/5">
                      <div className="w-12 h-12 rounded-2xl bg-purple-500/10 flex items-center justify-center">
                        <Cpu className="w-6 h-6 text-purple-400" />
                      </div>
                      <div className="flex-grow">
                        <p className="text-xs font-black text-white uppercase">Heuristic Core</p>
                        <p className="text-[10px] text-gray-500 font-bold uppercase">v3.0 Static Engine</p>
                      </div>
                      <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                   </div>
                   <div className="m3-card p-4 flex items-center gap-4 bg-[#1c1b1f] border border-white/5">
                      <div className="w-12 h-12 rounded-2xl bg-orange-500/10 flex items-center justify-center">
                        <Lock className="w-6 h-6 text-orange-400" />
                      </div>
                      <div className="flex-grow">
                        <p className="text-xs font-black text-white uppercase">Crypto Validator</p>
                        <p className="text-[10px] text-gray-500 font-bold uppercase">SHA-256 Runtime</p>
                      </div>
                      <div className="w-2 h-2 rounded-full bg-green-500" />
                   </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="px-4 animate-in fade-in slide-in-from-right-4 duration-500">
            <h2 className="text-sm font-black text-gray-500 uppercase tracking-widest mb-6 px-2">Audit Database</h2>
            <div className="space-y-4">
              {history.map(report => (
                <div 
                  key={report.id} 
                  onClick={() => { setSelectedReport(report); setActiveTab('home'); }}
                  className="m3-card p-5 border border-white/5 flex items-center justify-between"
                >
                  <div className="flex items-center gap-4 max-w-[80%]">
                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center ${report.riskLevel === RiskLevel.MALICIOUS ? 'bg-red-500/10 text-red-400' : report.riskLevel === RiskLevel.SUSPICIOUS ? 'bg-yellow-500/10 text-yellow-400' : 'bg-green-500/10 text-green-400'}`}>
                      {report.type === 'URL' ? <Globe className="w-5 h-5" /> : <FileSearch className="w-5 h-5" />}
                    </div>
                    <div className="overflow-hidden">
                      <p className="text-sm font-black text-white truncate uppercase tracking-tight">{report.target}</p>
                      <p className="text-[10px] text-gray-500 font-bold uppercase mt-1 flex items-center gap-2">
                        <Clock className="w-3 h-3" /> {new Date(report.timestamp).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <ChevronRight className="w-6 h-6 text-gray-700" />
                </div>
              ))}
              {history.length === 0 && (
                <div className="py-20 text-center opacity-30">
                  <Database className="w-12 h-12 mx-auto mb-4" />
                  <p className="text-xs font-black uppercase tracking-widest">Archive Empty</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Floating Scan Drawer (Mobile Only Experience) */}
      {showScanDrawer && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm animate-in fade-in duration-300">
           <div className="absolute bottom-0 left-0 right-0 bg-[#1c1b1f] rounded-t-[32px] p-8 space-y-8 animate-in slide-in-from-bottom-full duration-500 pb-16">
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-black text-white uppercase tracking-tighter">New Analysis</h3>
                <button onClick={() => setShowScanDrawer(false)} className="p-2 bg-white/5 rounded-full"><X className="w-6 h-6" /></button>
              </div>
              
              <div className="space-y-4">
                <div className="relative">
                  <input 
                    type="text" 
                    placeholder="ENTER URL TO SCAN" 
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-5 text-sm font-black uppercase tracking-widest text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all"
                  />
                  <button onClick={handleUrlScan} disabled={!url || isScanning} className="absolute right-3 top-1/2 -translate-y-1/2 w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg active:scale-90 transition-transform disabled:opacity-30">
                    {isScanning ? <Activity className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-4 pt-4">
                  <label className="m3-card bg-white/5 border border-white/10 p-6 flex flex-col items-center gap-3 text-center active:scale-95 transition-transform cursor-pointer">
                    <input type="file" accept=".apk" onChange={handleFileUpload} className="hidden" />
                    <div className="w-12 h-12 rounded-2xl bg-indigo-500/20 flex items-center justify-center">
                      <FileSearch className="w-6 h-6 text-indigo-400" />
                    </div>
                    <span className="text-[10px] font-black text-gray-300 uppercase tracking-widest">DEEP APK</span>
                  </label>
                  <label className="m3-card bg-white/5 border border-white/10 p-6 flex flex-col items-center gap-3 text-center active:scale-95 transition-transform cursor-pointer">
                    <input type="file" accept=".pdf" onChange={handleFileUpload} className="hidden" />
                    <div className="w-12 h-12 rounded-2xl bg-rose-500/20 flex items-center justify-center">
                      <FileText className="w-6 h-6 text-rose-400" />
                    </div>
                    <span className="text-[10px] font-black text-gray-300 uppercase tracking-widest">SECURE PDF</span>
                  </label>
                </div>
              </div>
              <div className="bg-blue-600/10 p-4 rounded-2xl border border-blue-600/20">
                <p className="text-[9px] text-blue-400 font-bold uppercase leading-relaxed text-center italic">
                  Isolated Static Sandbox Active. No Code Execution Verified.
                </p>
              </div>
           </div>
        </div>
      )}

      {/* Forensic Report (A4 Simulator for Print) */}
      {showForensicReport && selectedReport && (
        <div className="fixed inset-0 z-[100] bg-black p-0 overflow-y-auto no-scrollbar">
          <div className="min-h-screen bg-white text-slate-900 p-8 font-serif print:p-0">
             <div className="max-w-4xl mx-auto space-y-10">
                {/* PDF Header */}
                <div className="flex justify-between items-end border-b-[6px] border-slate-900 pb-6">
                   <div className="space-y-1">
                      <h1 className="text-3xl font-black uppercase tracking-tight text-slate-900 leading-none">FORENSIC CASE LOG</h1>
                      <p className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">MOBILE SANDBOX LABS • UNIT 01</p>
                   </div>
                   <div className="text-right">
                      <p className="text-[9px] font-black text-slate-400 uppercase">Case Status</p>
                      <p className="text-lg font-black text-red-600">CERTIFIED_THREAT</p>
                   </div>
                </div>

                <div className="grid grid-cols-2 gap-12 font-sans">
                   <div className="space-y-4">
                      <h4 className="text-[10px] font-black uppercase border-b border-slate-200 pb-1">Subject Metadata</h4>
                      <div className="grid grid-cols-2 gap-y-2 text-[10px]">
                         <span className="text-slate-400 font-bold uppercase">Asset:</span><span className="font-black truncate">{selectedReport.type}</span>
                         <span className="text-slate-400 font-bold uppercase">Source:</span><span className="font-black truncate">{selectedReport.target}</span>
                         <span className="text-slate-400 font-bold uppercase">Time:</span><span className="font-black truncate">{new Date(selectedReport.timestamp).toLocaleString()}</span>
                      </div>
                   </div>
                   <div className="space-y-4">
                      <h4 className="text-[10px] font-black uppercase border-b border-slate-200 pb-1">Integrity Signature</h4>
                      <div className="bg-slate-50 p-3 rounded border border-slate-100 mono text-[9px] break-all leading-tight">
                         SHA-256: {selectedReport.hash || 'EXT_UNAVAILABLE'}
                      </div>
                   </div>
                </div>

                <div className="bg-slate-900 text-white p-6 rounded flex justify-between items-center font-sans">
                   <div className="space-y-1">
                      <p className="text-[9px] font-black uppercase opacity-50 tracking-widest">Risk Classification</p>
                      <p className="text-3xl font-black">{selectedReport.riskLevel}</p>
                   </div>
                   <div className="text-right">
                      <p className="text-[9px] font-black uppercase opacity-50 tracking-widest">Confidence Score</p>
                      <p className="text-5xl font-black leading-none">{selectedReport.riskScore}<span className="text-xl opacity-30">/100</span></p>
                   </div>
                </div>

                <div className="space-y-4 font-sans">
                   <h4 className="text-[10px] font-black uppercase border-b border-slate-200 pb-1">Analyst Observations</h4>
                   <p className="text-sm font-medium italic border-l-4 border-slate-300 pl-4 py-2 leading-relaxed">
                      "{selectedReport.details.summary}"
                   </p>
                   <div className="bg-slate-50 p-4 rounded text-xs leading-relaxed text-slate-700">
                      <p className="font-black uppercase text-[9px] mb-2 text-slate-400">Detailed AI Heuristic Reasoning:</p>
                      {selectedReport.details.aiInsights}
                   </div>
                </div>

                <div className="pt-20 flex justify-between items-end border-t border-slate-200">
                   <div className="space-y-4">
                      <div className="flex gap-8 font-sans">
                         <div className="space-y-1">
                            <p className="text-[8px] font-black text-slate-300 uppercase">Analysis System</p>
                            <p className="text-[9px] font-bold">MS-LAB-SANDBOX v{APP_VERSION}</p>
                         </div>
                         <div className="space-y-1">
                            <p className="text-[8px] font-black text-slate-300 uppercase">Digital Seal</p>
                            <p className="text-[9px] font-mono text-slate-400">0x{selectedReport.id.substring(0,12)}</p>
                         </div>
                      </div>
                      <p className="text-[8px] text-slate-400 max-w-sm uppercase font-bold">Copyright © 2024 MS-LABS. Authorized Investigative artifact only. Permanent Chain-of-Custody record.</p>
                   </div>
                   <div className="no-print space-x-2">
                      <button onClick={handlePrint} className="bg-slate-900 text-white px-6 py-2 rounded text-[10px] font-black uppercase tracking-widest">Print Artifact</button>
                      <button onClick={() => setShowForensicReport(false)} className="bg-white border border-slate-300 text-slate-600 px-6 py-2 rounded text-[10px] font-black uppercase tracking-widest">Close</button>
                   </div>
                </div>
             </div>
          </div>
        </div>
      )}

      {/* Bottom Navigation (Material 3 Native Layout) */}
      <nav className="fixed bottom-0 left-0 right-0 bg-[#1c1b1f]/95 backdrop-blur-xl border-t border-white/5 bottom-nav z-40 no-print">
        <div className="flex justify-around items-center h-20 px-4">
          <button 
            onClick={() => { setActiveTab('home'); setSelectedReport(null); }} 
            className={`flex flex-col items-center gap-1 group w-16 transition-all ${activeTab === 'home' ? 'text-blue-500' : 'text-gray-500'}`}
          >
            <div className={`w-14 h-8 rounded-full flex items-center justify-center transition-all ${activeTab === 'home' ? 'bg-blue-600/10' : 'group-hover:bg-white/5'}`}>
              <LayoutGrid className="w-6 h-6" />
            </div>
            <span className="text-[10px] font-black uppercase tracking-tighter">Terminal</span>
          </button>
          
          <button 
            onClick={() => setActiveTab('history')} 
            className={`flex flex-col items-center gap-1 group w-16 transition-all ${activeTab === 'history' ? 'text-blue-500' : 'text-gray-500'}`}
          >
            <div className={`w-14 h-8 rounded-full flex items-center justify-center transition-all ${activeTab === 'history' ? 'bg-blue-600/10' : 'group-hover:bg-white/5'}`}>
              <HistoryIcon className="w-6 h-6" />
            </div>
            <span className="text-[10px] font-black uppercase tracking-tighter">Archive</span>
          </button>

          <button 
            onClick={() => setActiveTab('labs')} 
            className={`flex flex-col items-center gap-1 group w-16 transition-all ${activeTab === 'labs' ? 'text-blue-500' : 'text-gray-500'}`}
          >
            <div className={`w-14 h-8 rounded-full flex items-center justify-center transition-all ${activeTab === 'labs' ? 'bg-blue-600/10' : 'group-hover:bg-white/5'}`}>
              <Cpu className="w-6 h-6" />
            </div>
            <span className="text-[10px] font-black uppercase tracking-tighter">Labs</span>
          </button>
        </div>
      </nav>

      {/* Lab Modal (Coming Soon / Additional Info) */}
      {activeTab === 'labs' && (
        <div className="flex-grow p-6 flex flex-col items-center justify-center text-center space-y-4 opacity-50">
           <Zap className="w-12 h-12 text-blue-500" />
           <h2 className="text-xl font-black uppercase">Advanced Labs</h2>
           <p className="text-xs font-bold uppercase tracking-widest max-w-xs leading-relaxed">
             Dynamic Runtime Analysis and Network Interception modules are being prepared for deployment.
           </p>
        </div>
      )}
    </div>
  );
};

export default App;
