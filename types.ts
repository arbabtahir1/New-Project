
export enum RiskLevel {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  MALICIOUS = 'MALICIOUS',
  UNKNOWN = 'UNKNOWN'
}

export type AnalysisDepth = 'Quick' | 'Standard' | 'Deep';

export interface EngineResult {
  engine: string;
  category: 'malicious' | 'suspicious' | 'undetected' | 'type-unsupported';
  result: string | null;
  method: string;
}

export interface AnalysisReport {
  id: string;
  timestamp: number;
  type: 'URL' | 'APK' | 'PDF';
  target: string;
  hash?: string;
  encryptedPayload?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  analysisDepth: AnalysisDepth;
  engines: EngineResult[];
  details: {
    permissions?: string[];
    packageName?: string;
    pdfMetadata?: {
      author?: string;
      pages?: number;
      embeddedLinks?: string[];
    };
    summary: string;
    aiInsights?: string;
    threats?: string[];
  };
}
