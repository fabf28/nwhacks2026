export interface NetworkRequest {
  url: string;
  domain: string;
  resourceType: string;
  status?: number;
  isSuspicious: boolean;
  reason?: string;
}

export interface SuspiciousRequest extends NetworkRequest {
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  categories: string[];
  reasons: string[];
  riskScore: number;
}

export interface AnalysisSummary {
  totalRequests: number;
  suspiciousCount: number;
  criticalCount: number;
  highCount: number;
  categories: Record<string, number>;
  overallRisk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  totalRiskScore: number;
}

export interface DockerScanResult {
  success: boolean;
  containerId?: string;
  pageTitle?: string;
  finalUrl?: string;
  networkRequests: NetworkRequest[];
  suspiciousRequests: SuspiciousRequest[];
  totalRequests: number;
  thirdPartyDomains: string[];
  analysisSummary?: AnalysisSummary;
  error?: string;
}
