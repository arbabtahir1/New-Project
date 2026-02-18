
export enum RiskLevel {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  MALICIOUS = 'MALICIOUS',
  UNKNOWN = 'UNKNOWN'
}

export interface AnalysisReport {
  id: string;
  timestamp: number;
  type: 'URL' | 'APK' | 'PDF';
  target: string;
  hash?: string;
  riskScore: number; // 0-100
  riskLevel: RiskLevel;
  details: {
    permissions?: string[];
    packageName?: string;
    certificate?: string;
    pdfMetadata?: {
      author?: string;
      creator?: string;
      version?: string;
      pages?: number;
      embeddedLinks?: string[];
    };
    enginesDetected?: number;
    totalEngines?: number;
    summary: string;
    aiInsights?: string;
  };
}

export interface SandboxState {
  history: AnalysisReport[];
  isScanning: boolean;
  currentReport: AnalysisReport | null;
}
