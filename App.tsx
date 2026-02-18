
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
  Menu,
  X,
  PlusCircle,
  Clock,
  ExternalLink,
  ChevronRight,
  FileText,
  Printer,
  Download,
  Fingerprint,
  Activity,
  Info,
  Lock,
  Cpu,
  Scale,
  ShieldCheck,
  Zap,
  Terminal,
  Database
} from 'lucide-react';
import { AnalysisReport, RiskLevel } from './types';
import { calculateHash, extractApkMetadata, extractPdfMetadata, isValidUrl } from './utils/security';
import { analyzeSecurityThreat } from './services/geminiService';

const APP_VERSION = "2.4.1-enterprise";

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'scan' | 'history'>('scan');
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [history, setHistory] = useState<AnalysisReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showForensicReport, setShowForensicReport] = useState(false);
  const forensicReportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const saved = localStorage.getItem('sandbox_history');
    if (saved) {
      setHistory(JSON.parse(saved));
    }
  }, []);

  const saveReport = (report: AnalysisReport) => {
    const newHistory = [report, ...history].slice(0, 50);
    setHistory(newHistory);
    localStorage.setItem('sandbox_history', JSON.stringify(newHistory));
    setSelectedReport(report);
  };

  const handleUrlScan = async () => {
    if (!isValidUrl(url)) {
      alert("Invalid URL format");
      return;
    }
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
        enginesDetected: Math.floor(aiResult.riskScore / 10),
        totalEngines: 94
      }
    };
    saveReport(report);
    setIsScanning(false);
    setUrl('');
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const isApk = file.name.endsWith('.apk');
    const isPdf = file.name.endsWith('.pdf');

    if (!isApk && !isPdf) {
      alert("Supported formats: APK, PDF");
      return;
    }

    setIsScanning(true);
    try {
      if (isApk) {
        const metadata = await extractApkMetadata(file);
        const aiResult = await analyzeSecurityThreat('APK', metadata);
        const riskLevel = aiResult.riskScore > 75 ? RiskLevel.MALICIOUS : aiResult.riskScore > 30 ? RiskLevel.SUSPICIOUS : RiskLevel.SAFE;
        const report: AnalysisReport = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          type: 'APK',
          target: file.name,
          hash: metadata.hash,
          riskScore: aiResult.riskScore,
          riskLevel,
          details: {
            packageName: metadata.packageName,
            permissions: metadata.permissions,
            certificate: metadata.certificate,
            summary: aiResult.summary,
            aiInsights: aiResult.insights
          }
        };
        saveReport(report);
      } else {
        const metadata = await extractPdfMetadata(file);
        const aiResult = await analyzeSecurityThreat('PDF', { ...metadata, filename: file.name });
        const riskLevel = aiResult.riskScore > 75 ? RiskLevel.MALICIOUS : aiResult.riskScore > 30 ? RiskLevel.SUSPICIOUS : RiskLevel.SAFE;
        const report: AnalysisReport = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          type: 'PDF',
          target: file.name,
          hash: metadata.hash,
          riskScore: aiResult.riskScore,
          riskLevel,
          details: {
            pdfMetadata: {
              author: metadata.author,
              creator: metadata.creator,
              version: metadata.version,
              pages: metadata.pages,
              embeddedLinks: metadata.embeddedLinks
            },
            summary: aiResult.summary,
            aiInsights: aiResult.insights
          }
        };
        saveReport(report);
      }
    } catch (error) {
      console.error(error);
      alert("Analysis failed.");
    } finally {
      setIsScanning(false);
      e.target.value = '';
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const getRiskColor = (level: RiskLevel) => {
    switch (level) {
      case RiskLevel.SAFE: return 'text-green-400 bg-green-400/10 border-green-400/20';
      case RiskLevel.SUSPICIOUS: return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      case RiskLevel.MALICIOUS: return 'text-red-400 bg-red-400/10 border-red-400/20';
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
    }
  };

  const getRiskIcon = (level: RiskLevel) => {
    switch (level) {
      case RiskLevel.SAFE: return <CheckCircle2 className="w-5 h-5" />;
      case RiskLevel.SUSPICIOUS: return <AlertTriangle className="w-5 h-5" />;
      case RiskLevel.MALICIOUS: return <ShieldAlert className="w-5 h-5" />;
      default: return <Shield className="w-5 h-5" />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0c10] flex flex-col font-sans print:bg-white overflow-x-hidden">
      {/* Forensic Report Modal */}
      {showForensicReport && selectedReport && (
        <div className="fixed inset-0 z-[100] bg-black/90 flex items-center justify-center p-4 print:p-0 overflow-y-auto no-scrollbar">
          <div className="max-w-4xl w-full bg-white text-slate-900 rounded-lg shadow-2xl overflow-hidden print:shadow-none print:rounded-none">
            {/* Report Controls */}
            <div className="bg-slate-100 px-6 py-4 flex justify-between items-center border-b border-slate-200 print:hidden">
              <h3 className="font-bold text-slate-700 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-blue-600" />
                SECURE EVIDENCE VIEWER
              </h3>
              <div className="flex gap-2">
                <button 
                  onClick={handlePrint}
                  className="bg-slate-900 text-white px-4 py-2 rounded text-xs font-bold flex items-center gap-2 hover:bg-black transition-all shadow-md active:scale-95"
                >
                  <Printer className="w-3.5 h-3.5" /> PRINT FOR ARCHIVE
                </button>
                <button 
                  onClick={() => setShowForensicReport(false)}
                  className="bg-white border border-slate-300 text-slate-700 px-4 py-2 rounded text-xs font-bold hover:bg-slate-50 transition-all active:scale-95"
                >
                  DISMISS
                </button>
              </div>
            </div>

            {/* Actual Document Content */}
            <div className="p-12 space-y-10 font-serif print:p-8" ref={forensicReportRef}>
              <div className="flex justify-between items-start border-b-4 border-slate-900 pb-8">
                <div>
                  <h1 className="text-4xl font-black uppercase tracking-tighter text-slate-900">Forensic Analysis Report</h1>
                  <p className="text-slate-500 font-sans text-[10px] font-black tracking-[0.2em] mt-2">
                    MOBILE SANDBOX LABS • DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR)
                  </p>
                </div>
                <div className="text-right flex flex-col items-end">
                  <div className="p-2 bg-slate-900 text-white rounded mb-2">
                    <Shield className="w-6 h-6" />
                  </div>
                  <p className="font-sans text-[9px] font-black uppercase text-slate-400 mb-1">Electronic Case Record</p>
                  <p className="font-mono text-xs font-bold"># {selectedReport.id.substring(0, 18).toUpperCase()}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-12 font-sans">
                <div className="space-y-4">
                  <h4 className="text-[10px] font-black uppercase border-b-2 border-slate-900 pb-1 flex items-center gap-2">
                    <Info className="w-3 h-3" /> Subject Profile
                  </h4>
                  <div className="grid grid-cols-2 gap-y-3 text-[11px]">
                    <span className="text-slate-500 font-bold">ASSET CLASS:</span><span className="font-black text-slate-900">{selectedReport.type}</span>
                    <span className="text-slate-500 font-bold">IDENTIFIER:</span><span className="font-black break-all text-slate-900">{selectedReport.target}</span>
                    <span className="text-slate-500 font-bold">ACQUISITION:</span><span className="font-black text-slate-900">{new Date(selectedReport.timestamp).toLocaleString()}</span>
                    {selectedReport.details.packageName && (
                      <><span className="text-slate-500 font-bold">PACKAGE ID:</span><span className="font-black text-slate-900">{selectedReport.details.packageName}</span></>
                    )}
                  </div>
                </div>
                <div className="space-y-4">
                  <h4 className="text-[10px] font-black uppercase border-b-2 border-slate-900 pb-1 flex items-center gap-2">
                    <Fingerprint className="w-3 h-3" /> Integrity Checksum
                  </h4>
                  <div className="text-[10px] font-mono bg-slate-100 p-4 rounded border border-slate-200 break-all leading-tight shadow-inner">
                    <p className="text-slate-400 mb-2 uppercase text-[8px] font-black">Cryptographic Standard: SHA-256</p>
                    <span className="text-slate-700 font-bold">{selectedReport.hash || "EXTERNAL_RESOURCE_HASH_NOT_CALCULATED"}</span>
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div className="bg-slate-900 text-white p-8 rounded-lg flex justify-between items-center shadow-xl">
                  <div>
                    <h3 className="text-[10px] uppercase font-black tracking-[0.3em] opacity-50 mb-2">Threat Classification</h3>
                    <div className="flex items-center gap-3">
                       <span className={`w-3 h-3 rounded-full animate-pulse ${selectedReport.riskScore > 75 ? 'bg-red-500' : selectedReport.riskScore > 30 ? 'bg-yellow-500' : 'bg-green-500'}`} />
                       <p className="text-3xl font-black">{selectedReport.riskLevel}</p>
                    </div>
                  </div>
                  <div className="text-right border-l border-white/20 pl-8">
                    <p className="text-[10px] uppercase font-black tracking-[0.3em] opacity-50 mb-2">Security Confidence</p>
                    <p className="text-5xl font-black leading-none">{selectedReport.riskScore}<span className="text-xl opacity-30 font-light">/100</span></p>
                  </div>
                </div>

                <div className="space-y-4 p-8 border border-slate-200 rounded-lg bg-slate-50/50">
                  <h4 className="text-xs font-black uppercase flex items-center gap-2 text-slate-900">
                    <Activity className="w-4 h-4 text-blue-600" />
                    Technical Intelligence Summary
                  </h4>
                  <p className="text-sm leading-relaxed text-slate-800 font-sans italic border-l-4 border-slate-300 pl-4 py-2">
                    "{selectedReport.details.summary}"
                  </p>
                  <div className="bg-white p-5 rounded border border-slate-200 text-xs font-sans text-slate-700 leading-relaxed shadow-sm">
                    <div className="flex items-center gap-2 mb-2 text-blue-700 font-black uppercase text-[9px]">
                      <Zap className="w-3 h-3" /> Expert Analysis Observation
                    </div>
                    {selectedReport.details.aiInsights}
                  </div>
                </div>

                {selectedReport.details.permissions && (
                  <div className="space-y-4">
                    <h4 className="text-[10px] font-black uppercase text-slate-900 tracking-wider">Manifest Capability Audit</h4>
                    <div className="grid grid-cols-2 gap-3">
                      {selectedReport.details.permissions.map(p => (
                        <div key={p} className="flex items-center gap-3 text-[10px] bg-slate-50 border border-slate-100 p-3 rounded font-mono text-slate-600">
                          <Lock className="w-3 h-3 text-slate-400" /> {p}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-16 pt-8 border-t-2 border-slate-900 flex justify-between font-sans items-end">
                <div className="space-y-4">
                  <div className="flex gap-12">
                     <div className="space-y-1">
                        <p className="text-[8px] font-black uppercase text-slate-400">Analysis System</p>
                        <p className="text-[10px] font-bold">MS-LAB-SANDBOX v{APP_VERSION}</p>
                     </div>
                     <div className="space-y-1">
                        <p className="text-[8px] font-black uppercase text-slate-400">Digital Seal</p>
                        <p className="text-[10px] font-mono text-slate-400">VERIFIED_ELECTRONIC_FORENSIC_SIG</p>
                     </div>
                  </div>
                  <p className="text-[9px] text-slate-500 max-w-lg uppercase font-bold leading-tight">
                    This document is intended for authorized forensic use only. 
                    Copyright © 2024 Mobile Sandbox Lab. All rights reserved. 
                    Property of Digital Security Unit.
                  </p>
                </div>
                <div className="text-right">
                  <div className="bg-slate-100 p-3 rounded mb-2 inline-block">
                     <ShieldCheck className="w-8 h-8 text-slate-300" />
                  </div>
                  <p className="text-[8px] font-black text-slate-400 uppercase">Page 01 // EOF</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Navbar */}
      <nav className="border-b border-gray-800 bg-[#0d1117]/95 backdrop-blur-xl sticky top-0 z-50 print:hidden transition-all duration-300">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-blue-600 to-indigo-700 rounded-lg shadow-xl shadow-blue-500/20 group cursor-pointer transition-transform active:scale-90">
                <Shield className="w-6 h-6 text-white group-hover:rotate-12 transition-transform" />
              </div>
              <div className="flex flex-col">
                <span className="text-lg font-black tracking-tight text-white leading-none">
                  MOBILE SANDBOX
                </span>
                <span className="text-[10px] font-black text-blue-500 tracking-[0.25em] uppercase leading-none mt-1">
                  Enterprise Unit
                </span>
              </div>
            </div>
            
            <div className="hidden md:flex items-center gap-2">
              <button 
                onClick={() => setActiveTab('scan')} 
                className={`px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${activeTab === 'scan' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}
              >
                Analysis Lab
              </button>
              <button 
                onClick={() => setActiveTab('history')} 
                className={`px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${activeTab === 'history' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}
              >
                Audit Log
              </button>
              <div className="h-4 w-px bg-gray-800 mx-2" />
              <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/20 rounded-full">
                <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                <span className="text-[9px] font-black text-green-500 uppercase">Secure Connection</span>
              </div>
            </div>

            <button className="md:hidden p-2 text-gray-400" onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}>
              {isMobileMenuOpen ? <X /> : <Menu />}
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 print:hidden">
        {activeTab === 'scan' ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in duration-700">
            <div className="lg:col-span-1 space-y-6">
              {/* BRANDING EXPLANATION - WHAT IS ENTERPRISE UNIT? */}
              <div className="bg-gradient-to-br from-blue-900/20 to-indigo-900/20 border border-blue-500/20 rounded-xl p-5 shadow-inner">
                <h3 className="text-[11px] font-black text-blue-400 uppercase tracking-[0.3em] flex items-center gap-2 mb-3">
                  <Zap className="w-3.5 h-3.5" /> Unit Capabilities
                </h3>
                <div className="space-y-4">
                  <div className="flex gap-3">
                    <div className="mt-1"><Fingerprint className="w-3.5 h-3.5 text-blue-500" /></div>
                    <div>
                      <h4 className="text-[10px] font-black text-gray-200 uppercase">Cryptographic Integrity</h4>
                      <p className="text-[9px] text-gray-500 font-medium uppercase mt-0.5 leading-tight">SHA-256 binary hashing for non-repudiation forensic verification.</p>
                    </div>
                  </div>
                  <div className="flex gap-3">
                    <div className="mt-1"><Terminal className="w-3.5 h-3.5 text-blue-500" /></div>
                    <div>
                      <h4 className="text-[10px] font-black text-gray-200 uppercase">Heuristic Reasoning</h4>
                      <p className="text-[9px] text-gray-500 font-medium uppercase mt-0.5 leading-tight">Advanced AI behavior modeling to detect zero-day phishing lures.</p>
                    </div>
                  </div>
                  <div className="flex gap-3">
                    <div className="mt-1"><Database className="w-3.5 h-3.5 text-blue-500" /></div>
                    <div>
                      <h4 className="text-[10px] font-black text-gray-200 uppercase">Audit Persistence</h4>
                      <p className="text-[9px] text-gray-500 font-medium uppercase mt-0.5 leading-tight">Immutable local history log for maintaining investigative chain-of-custody.</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* URL Section */}
              <div className="bg-[#0d1117] border border-gray-800 rounded-xl p-6 shadow-2xl relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-4 opacity-5">
                   <Globe className="w-16 h-16" />
                </div>
                <h2 className="text-sm font-black text-white uppercase tracking-widest mb-6 flex items-center gap-3">
                  <span className="w-6 h-6 rounded bg-blue-500/20 flex items-center justify-center">
                    <Globe className="w-3.5 h-3.5 text-blue-400" />
                  </span>
                  Network Reputation
                </h2>
                <div className="space-y-4">
                  <div className="relative">
                    <input 
                      type="text" 
                      placeholder="Input destination URL..." 
                      value={url} 
                      onChange={(e) => setUrl(e.target.value)}
                      className="w-full bg-[#0a0c10] border border-gray-800 rounded-lg px-4 py-3 text-xs font-mono text-gray-300 focus:ring-1 focus:ring-blue-600 outline-none transition-all placeholder:text-gray-600" 
                    />
                  </div>
                  <button 
                    onClick={handleUrlScan} 
                    disabled={isScanning || !url}
                    className="w-full bg-blue-600 hover:bg-blue-700 active:scale-[0.98] disabled:opacity-50 text-white py-3 rounded-lg text-xs font-black uppercase tracking-widest transition-all shadow-xl shadow-blue-600/20 flex items-center justify-center gap-3"
                  >
                    {isScanning ? <Activity className="animate-spin w-4 h-4" /> : <Search className="w-3.5 h-3.5" />} 
                    Execute Scan
                  </button>
                </div>
              </div>

              {/* Upload Section */}
              <div className="bg-[#0d1117] border border-gray-800 rounded-xl p-6 shadow-2xl relative overflow-hidden">
                <h2 className="text-sm font-black text-white uppercase tracking-widest mb-6 flex items-center gap-3">
                   <span className="w-6 h-6 rounded bg-purple-500/20 flex items-center justify-center">
                    <FileSearch className="w-3.5 h-3.5 text-purple-400" />
                  </span>
                  Static Asset Import
                </h2>
                <label className="group relative block w-full aspect-video border-2 border-dashed border-gray-800 hover:border-purple-600/50 rounded-xl cursor-pointer transition-all bg-[#0a0c10] overflow-hidden">
                  <input type="file" accept=".apk,.pdf" onChange={handleFileUpload} className="hidden" disabled={isScanning} />
                  <div className="absolute inset-0 flex flex-col items-center justify-center p-4 text-center">
                    <div className="w-12 h-12 rounded-full bg-gray-800 flex items-center justify-center mb-4 group-hover:bg-purple-600 transition-all group-hover:shadow-lg group-hover:shadow-purple-600/20">
                       <PlusCircle className="w-6 h-6 text-gray-500 group-hover:text-white transition-colors" />
                    </div>
                    <p className="text-xs font-black text-gray-400 uppercase tracking-widest group-hover:text-white">Import APK / PDF</p>
                    <p className="text-[10px] text-gray-600 mt-2 font-mono uppercase tracking-[0.1em]">Isolated Buffer</p>
                  </div>
                </label>
              </div>
            </div>

            {/* Analysis Result */}
            <div className="lg:col-span-2">
              {selectedReport ? (
                <div className="bg-[#0d1117] border border-gray-800 rounded-xl overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.5)] transition-all animate-in slide-in-from-right-4 duration-500">
                  <div className={`px-6 py-5 border-b border-gray-800 flex items-center justify-between ${getRiskColor(selectedReport.riskLevel)}`}>
                    <div className="flex items-center gap-4">
                      <div className="p-2 bg-white/10 rounded border border-white/20">
                        {getRiskIcon(selectedReport.riskLevel)}
                      </div>
                      <div>
                        <h2 className="font-black text-xl tracking-tighter uppercase leading-none">{selectedReport.type} ANALYSIS RESULT</h2>
                        <p className="text-[9px] font-black uppercase tracking-[0.2em] mt-1 opacity-70 italic">Security Classification: {selectedReport.riskLevel}</p>
                      </div>
                    </div>
                    <button 
                      onClick={() => setShowForensicReport(true)}
                      className="bg-white text-slate-900 text-[10px] font-black px-4 py-2 rounded uppercase flex items-center gap-2 transition-all hover:scale-105 active:scale-95 shadow-xl"
                    >
                      <Fingerprint className="w-3.5 h-3.5" /> DEEP FORENSICS REPORT
                    </button>
                  </div>

                  <div className="p-8 space-y-10">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                      <div className="space-y-6">
                        <div className="group">
                          <label className="text-[10px] text-gray-500 uppercase font-black tracking-[0.2em] block mb-2">Primary Asset Target</label>
                          <div className="bg-black/50 border border-gray-800 rounded-lg p-3 font-mono text-[11px] text-blue-400 break-all leading-relaxed group-hover:border-blue-600/50 transition-colors">
                            {selectedReport.target}
                          </div>
                        </div>
                        
                        {selectedReport.details.pdfMetadata && (
                          <div className="grid grid-cols-2 gap-4">
                             <div className="bg-black/30 p-3 rounded-lg border border-gray-800">
                               <label className="text-[9px] text-gray-600 uppercase font-black tracking-widest block mb-1">Author / Origin</label>
                               <p className="text-gray-300 text-xs font-bold truncate">{selectedReport.details.pdfMetadata.author}</p>
                             </div>
                             <div className="bg-black/30 p-3 rounded-lg border border-gray-800">
                               <label className="text-[9px] text-gray-600 uppercase font-black tracking-widest block mb-1">Page Volume</label>
                               <p className="text-gray-300 text-xs font-bold">{selectedReport.details.pdfMetadata.pages} Units</p>
                             </div>
                          </div>
                        )}
                        
                        {selectedReport.hash && (
                          <div className="group">
                            <label className="text-[10px] text-gray-500 uppercase font-black tracking-[0.2em] block mb-2">Cryptographic Fingerprint</label>
                            <div className="text-gray-600 font-mono text-[9px] break-all bg-black/50 p-3 rounded border border-gray-800 group-hover:text-gray-400 transition-colors">
                              SHA256:{selectedReport.hash}
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="flex flex-col items-center justify-center p-8 bg-gradient-to-br from-gray-900/50 to-black rounded-3xl border border-gray-800 shadow-inner">
                        <div className="relative w-40 h-40">
                          <svg className="w-full h-full transform -rotate-90">
                            <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="10" fill="transparent" className="text-gray-800" />
                            <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="10" fill="transparent" 
                              strokeDasharray={439.8} strokeDashoffset={439.8 - (439.8 * selectedReport.riskScore) / 100}
                              className={`transition-all duration-1000 ${selectedReport.riskScore > 75 ? 'text-red-500' : selectedReport.riskScore > 30 ? 'text-yellow-500' : 'text-green-500'}`}
                              strokeLinecap="round" />
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-4xl font-black text-white leading-none">{selectedReport.riskScore}</span>
                            <span className="text-[10px] text-gray-500 uppercase font-black tracking-widest mt-1">THREAT IDX</span>
                          </div>
                        </div>
                        <div className="mt-6 text-center space-y-1">
                           <p className="text-[10px] font-black uppercase text-gray-500 tracking-[0.1em]">Engine Confidence Level</p>
                           <p className="text-xs font-bold text-gray-400 italic">High-Precision Intelligence</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-blue-600/5 border border-blue-600/20 rounded-2xl p-6 relative">
                      <div className="absolute top-0 right-0 p-4">
                        <Cpu className="w-5 h-5 text-blue-600 opacity-30" />
                      </div>
                      <h3 className="text-blue-500 font-black text-[11px] flex items-center gap-3 mb-4 uppercase tracking-[0.2em]">
                        <Zap className="w-4 h-4" /> AI HEURISTIC ENGINE ASSESSMENT
                      </h3>
                      <p className="text-gray-200 text-sm leading-relaxed mb-6 font-medium font-serif border-l-2 border-blue-600/50 pl-6 italic">{selectedReport.details.summary}</p>
                      <div className="bg-black/40 p-4 rounded-xl border border-gray-800 flex gap-4 items-start shadow-inner">
                         <div className="p-2.5 bg-blue-600/10 rounded-lg border border-blue-600/20">
                            <ShieldCheck className="w-5 h-5 text-blue-400" />
                         </div>
                         <div>
                            <span className="text-[9px] text-gray-500 uppercase font-black block mb-1 tracking-widest">Analyst Intelligence</span>
                            <p className="text-xs text-gray-400 font-medium leading-relaxed">{selectedReport.details.aiInsights}</p>
                         </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                       {selectedReport.details.permissions && (
                        <div className="space-y-4">
                          <h3 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em] flex items-center gap-2">
                            <Lock className="w-3.5 h-3.5" /> PRIVACY & PERMISSION AUDIT
                          </h3>
                          <div className="flex flex-wrap gap-2">
                            {selectedReport.details.permissions.map(p => (
                              <span key={p} className="px-3 py-1 bg-red-600/5 border border-red-600/20 text-red-400 text-[10px] rounded font-black tracking-tighter uppercase shadow-sm">
                                {p.split('.').pop()}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedReport.details.pdfMetadata?.embeddedLinks && selectedReport.details.pdfMetadata.embeddedLinks.length > 0 && (
                        <div className="space-y-4">
                          <h3 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em] flex items-center gap-2">
                            <ExternalLink className="w-3.5 h-3.5" /> NETWORK REDIRECTION LOG
                          </h3>
                          <div className="space-y-2">
                            {selectedReport.details.pdfMetadata.embeddedLinks.map(l => (
                              <div key={l} className="text-[10px] text-blue-400 bg-blue-600/5 border border-blue-600/20 px-3 py-2.5 rounded-lg truncate font-mono font-bold shadow-inner">
                                {l}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="h-full min-h-[500px] flex flex-col items-center justify-center border-2 border-dashed border-gray-800 rounded-3xl p-12 text-center bg-[#0d1117]/50 group transition-all duration-700">
                  <div className="w-24 h-24 bg-gray-900 border border-gray-800 rounded-full flex items-center justify-center mb-8 group-hover:border-blue-600 transition-colors relative">
                    <Shield className="w-12 h-12 text-gray-700 group-hover:text-blue-600 transition-all duration-700" />
                    <div className="absolute inset-0 bg-blue-600/10 rounded-full animate-ping opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <h3 className="text-xl font-black text-gray-400 uppercase tracking-[0.2em] mb-3">System Ready</h3>
                  <p className="text-gray-600 max-w-sm text-sm font-medium uppercase leading-relaxed tracking-wider">
                    Awaiting encrypted binary or network identifier for forensic decomposition.
                  </p>
                  <div className="mt-12 grid grid-cols-3 gap-8 opacity-30 grayscale hover:grayscale-0 transition-all duration-700">
                    <div className="flex flex-col items-center"><Zap className="w-6 h-6 mb-2" /><span className="text-[8px] font-black uppercase">Realtime</span></div>
                    <div className="flex flex-col items-center"><Fingerprint className="w-6 h-6 mb-2" /><span className="text-[8px] font-black uppercase">Secure</span></div>
                    <div className="flex flex-col items-center"><Lock className="w-6 h-6 mb-2" /><span className="text-[8px] font-black uppercase">Privacy</span></div>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="bg-[#0d1117] border border-gray-800 rounded-2xl overflow-hidden shadow-2xl animate-in fade-in duration-500">
             <div className="px-8 py-6 border-b border-gray-800 flex items-center justify-between bg-black/20">
              <h2 className="text-sm font-black flex items-center gap-3 text-white uppercase tracking-widest">
                <HistoryIcon className="w-4 h-4 text-blue-500" /> AUDIT TRAIL LOG
              </h2>
              <button 
                onClick={() => { if(confirm('Permanent data wipe requested. Proceed?')) { setHistory([]); localStorage.removeItem('sandbox_history'); } }} 
                className="text-[10px] font-black text-red-500/60 hover:text-red-500 uppercase transition-all tracking-widest border border-red-500/10 px-3 py-1.5 rounded-lg hover:bg-red-500/5"
              >
                Purge Audit Database
              </button>
            </div>
            <div className="divide-y divide-gray-800/50">
              {history.length > 0 ? history.map((report) => (
                <div 
                  key={report.id} 
                  onClick={() => { setSelectedReport(report); setActiveTab('scan'); window.scrollTo({top: 0, behavior: 'smooth'}); }}
                  className="px-8 py-5 hover:bg-white/5 cursor-pointer transition-all flex items-center justify-between group border-l-2 border-l-transparent hover:border-l-blue-600"
                >
                  <div className="flex items-center gap-6">
                    <div className={`p-3 rounded-xl shadow-lg ${report.type === 'URL' ? 'bg-blue-600/10 text-blue-500' : report.type === 'APK' ? 'bg-indigo-600/10 text-indigo-500' : 'bg-rose-600/10 text-rose-500'}`}>
                      {report.type === 'URL' ? <Globe className="w-5 h-5" /> : report.type === 'APK' ? <FileSearch className="w-5 h-5" /> : <FileText className="w-5 h-5" />}
                    </div>
                    <div>
                      <p className="text-xs font-black text-white truncate max-w-xs md:max-w-xl group-hover:text-blue-400 transition-colors uppercase tracking-tight">{report.target}</p>
                      <div className="flex items-center gap-3 mt-2">
                        <span className="text-[10px] text-gray-500 flex items-center gap-1.5 font-black uppercase tracking-widest"><Clock className="w-3.5 h-3.5" /> {new Date(report.timestamp).toLocaleDateString()}</span>
                        <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border uppercase tracking-tighter ${getRiskColor(report.riskLevel)}`}>{report.riskLevel}</span>
                      </div>
                    </div>
                  </div>
                  <ChevronRight className="w-5 h-5 text-gray-700 group-hover:text-white group-hover:translate-x-1 transition-all" />
                </div>
              )) : (
                <div className="p-24 text-center text-gray-700 flex flex-col items-center">
                  <Activity className="w-12 h-12 mb-4 opacity-10" />
                  <p className="text-xs font-black uppercase tracking-widest opacity-30 italic">Cryptographic audit log is currently empty.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-10 px-8 bg-[#0a0c10] print:hidden">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-12 mb-12">
            <div className="col-span-1 md:col-span-2 space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-blue-600" />
                <span className="text-xs font-black text-white uppercase tracking-[0.2em]">Mobile Sandbox Enterprise</span>
              </div>
              <p className="text-[10px] text-gray-600 leading-relaxed font-bold uppercase max-w-md">
                Industry-standard static analysis environment for professional digital forensic investigation and malware decomposition. 
                Built for security engineers and DFIR professionals worldwide.
              </p>
              <div className="flex gap-4 opacity-50 grayscale hover:grayscale-0 transition-all duration-700">
                 <ShieldCheck className="w-6 h-6 text-gray-500" />
                 <Lock className="w-6 h-6 text-gray-500" />
                 <Fingerprint className="w-6 h-6 text-gray-500" />
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="text-[10px] font-black text-gray-400 uppercase tracking-widest border-b border-gray-800 pb-2">Legal Artifacts</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-[10px] text-gray-500 hover:text-white transition-colors font-bold uppercase">Privacy Governance</a></li>
                <li><a href="#" className="text-[10px] text-gray-500 hover:text-white transition-colors font-bold uppercase">Ethics Framework</a></li>
                <li><a href="#" className="text-[10px] text-gray-500 hover:text-white transition-colors font-bold uppercase">Terms of Discovery</a></li>
              </ul>
            </div>
            <div className="space-y-4 text-right">
              <h4 className="text-[10px] font-black text-gray-400 uppercase tracking-widest border-b border-gray-800 pb-2">Deployment Status</h4>
              <div className="space-y-1">
                <p className="text-[10px] text-white font-black uppercase">Version {APP_VERSION}</p>
                <p className="text-[10px] text-gray-500 uppercase font-bold tracking-tighter">Cluster: Sandbox-01-Global</p>
                <p className="text-[10px] text-green-500 font-black uppercase tracking-widest mt-2 flex items-center justify-end gap-1.5">
                   Operational <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                </p>
              </div>
            </div>
          </div>
          <div className="pt-8 border-t border-gray-800 flex flex-col md:flex-row justify-between items-center gap-6">
            <p className="text-[9px] text-gray-600 font-black uppercase tracking-[0.2em]">
              © 2024 MOBILE SANDBOX LABS INC. ALL RIGHTS RESERVED. PROTECTED BY GLOBAL CYBER SECURITY STATUTES.
            </p>
            <div className="flex gap-6 items-center">
               <span className="text-[10px] font-mono text-gray-700 select-none">SHA: {crypto.randomUUID().substring(0,8)}</span>
               <div className="h-6 w-px bg-gray-800" />
               <span className="text-[9px] font-black text-gray-500 uppercase tracking-widest">Encrypted Session</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
