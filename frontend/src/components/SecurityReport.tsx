import React, { useState } from 'react';
import {
    CheckCircle,
    AlertTriangle,
    ShieldAlert,
    Globe,
    Lock,
    ShieldCheck,
    Server,
    Download,
    Network,
    Wifi,
    Shield,
    FileCheck,
    Cookie,
    MessageCircle
} from 'lucide-react';
import { generatePDFReport } from '../utils/pdfGenerator';
import ChatPanel from './ChatPanel';

interface ReportData {
    url: string;
    score: number;
    domainAge: string;
    sslStatus: 'valid' | 'expired' | 'none' | 'invalid';
    registrar: string;
    serverLocation: string;
    sandboxResult: 'clean' | 'suspicious' | 'malicious';
    isp?: string;
    // SSL/TLS data
    ssl?: {
        tlsVersion: string;
        cipher: string;
        cipherStrength: 'strong' | 'moderate' | 'weak';
        certificateChain?: { subject: string; issuer: string }[];
    };
    // Network data
    reverseDns?: {
        matches: boolean;
        hostnames: string[];
    };
    portScan?: {
        openPorts: number[];
        suspiciousPorts: number[];
        isSuspicious: boolean;
    };
    ipReputation?: {
        abuseConfidenceScore: number;
        totalReports: number;
        isSuspicious: boolean;
    };
    safeBrowsing?: {
        isSafe: boolean;
        threats: string[];
    };
    // HTTP Security
    securityHeaders?: {
        score: number;
        grade: 'A' | 'B' | 'C' | 'D' | 'F';
        headers: { name: string; status: string }[];
    };
    cookieSecurity?: {
        totalCookies: number;
        secureCookies: number;
        hasIssues: boolean;
    };
    // Vulnerability data
    sensitiveFiles?: {
        exposedFiles: { path: string; severity: string; description: string }[];
        hasVulnerabilities: boolean;
        criticalCount: number;
        highCount: number;
    };
    versionDisclosure?: {
        serverVersion: string | null;
        poweredBy: string | null;
        hasDisclosure: boolean;
        riskLevel: string;
    };
    adminPanels?: {
        foundPanels: { path: string; type: string }[];
        hasExposedPanels: boolean;
    };
    // Docker sandbox data
    dockerScan?: {
        success: boolean;
        pageTitle?: string;
        finalUrl?: string;
        networkRequests: Array<{
            url: string;
            domain: string;
            resourceType: string;
            status?: number;
            isSuspicious: boolean;
            reason?: string;
        }>;
        suspiciousRequests: Array<{
            url: string;
            domain: string;
            resourceType: string;
            status?: number;
            isSuspicious: boolean;
            reason?: string;
            riskLevel?: 'low' | 'medium' | 'high' | 'critical';
            categories?: string[];
            reasons?: string[];
            riskScore?: number;
        }>;
        totalRequests: number;
        thirdPartyDomains: string[];
        analysisSummary?: {
            totalRequests: number;
            suspiciousCount: number;
            criticalCount: number;
            highCount: number;
            categories: Record<string, number>;
            overallRisk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
            totalRiskScore: number;
        };
        error?: string;
    };
}

const SecurityReport: React.FC<{ data: ReportData }> = ({ data }) => {
    const [isChatOpen, setIsChatOpen] = useState(false);

    const getScoreColor = (score: number) => {
        if (score >= 80) return 'var(--success)';
        if (score >= 50) return 'var(--warning)';
        return 'var(--danger)';
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'clean': case 'success': return <CheckCircle color="var(--success)" size={18} />;
            case 'suspicious': case 'warning': return <AlertTriangle color="var(--warning)" size={18} />;
            case 'malicious': case 'danger': return <ShieldAlert color="var(--danger)" size={18} />;
            default: return null;
        }
    };

    const handleDownloadPDF = () => {
        generatePDFReport(data);
    };

    const cardStyle = { padding: '20px', background: 'rgba(255,255,255,0.02)' };
    const headerStyle = { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' };
    const rowStyle = { display: 'flex', justifyContent: 'space-between' };

    return (
        <div className="glass-card" style={{ padding: '32px' }}>
            {/* Header with Score */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
                <div>
                    <h2 style={{ fontSize: '1.5rem', marginBottom: '4px' }}>Security Intelligence Report</h2>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Analyzed: {data.url}</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '2.5rem', fontWeight: 800, color: getScoreColor(data.score), textShadow: `0 0 20px ${getScoreColor(data.score)}44` }}>
                        {data.score}
                    </div>
                    <span className={`score-badge ${data.score >= 80 ? 'score-safe' : data.score >= 50 ? 'score-warn' : 'score-danger'}`}>
                        {data.score >= 80 ? 'Secure' : data.score >= 50 ? 'Warning' : 'Danger'}
                    </span>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
                {/* 1. Domain Info */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Globe size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Domain Information</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>Creation Date</span><span>{data.domainAge}</span></div>
                        <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>Registrar</span><span>{data.registrar}</span></div>
                    </div>
                </div>

                {/* 2. SSL/TLS - Enhanced */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Lock size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>SSL/TLS Certificate</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Status</span>
                            <span style={{ color: data.sslStatus === 'valid' ? 'var(--success)' : 'var(--danger)' }}>{data.sslStatus?.toUpperCase()}</span>
                        </div>
                        {data.ssl && (
                            <>
                                <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>TLS Version</span><span>{data.ssl.tlsVersion}</span></div>
                                <div style={rowStyle}>
                                    <span style={{ color: 'var(--text-muted)' }}>Cipher</span>
                                    <span style={{ fontSize: '0.8rem', maxWidth: '60%', textAlign: 'right' }}>{data.ssl.cipher}</span>
                                </div>
                                <div style={rowStyle}>
                                    <span style={{ color: 'var(--text-muted)' }}>Strength</span>
                                    <span style={{ color: data.ssl.cipherStrength === 'strong' ? 'var(--success)' : data.ssl.cipherStrength === 'moderate' ? 'var(--warning)' : 'var(--danger)' }}>
                                        {data.ssl.cipherStrength?.toUpperCase()}
                                    </span>
                                </div>
                            </>
                        )}
                    </div>
                </div>

                {/* 3. Infrastructure */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Server size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Infrastructure</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>Location</span><span>{data.serverLocation}</span></div>
                        <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>Hosting</span><span>{data.isp || 'Unknown'}</span></div>
                    </div>
                </div>

                {/* 4. Reverse DNS */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Network size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Reverse DNS</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>PTR Match</span>
                            {data.reverseDns ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {getStatusIcon(data.reverseDns.matches ? 'success' : 'warning')}
                                    <span style={{ color: data.reverseDns.matches ? 'var(--success)' : 'var(--warning)' }}>{data.reverseDns.matches ? 'VERIFIED' : 'NO MATCH'}</span>
                                </div>
                            ) : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                        </div>
                    </div>
                </div>

                {/* 5. Port Scan */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Wifi size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Port Scan</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Status</span>
                            {data.portScan ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {getStatusIcon(data.portScan.isSuspicious ? 'warning' : 'success')}
                                    <span style={{ color: data.portScan.isSuspicious ? 'var(--warning)' : 'var(--success)' }}>{data.portScan.isSuspicious ? 'SUSPICIOUS' : 'CLEAN'}</span>
                                </div>
                            ) : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                        </div>
                        <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>Open Ports</span><span>{data.portScan?.openPorts?.length || 0} ({data.portScan?.suspiciousPorts?.length || 0} risky)</span></div>
                    </div>
                </div>

                {/* 6. IP Reputation */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Shield size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>IP Reputation</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Abuse Score</span>
                            {data.ipReputation ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {getStatusIcon(data.ipReputation.isSuspicious ? 'danger' : 'success')}
                                    <span style={{ color: data.ipReputation.abuseConfidenceScore > 25 ? 'var(--danger)' : 'var(--success)' }}>{data.ipReputation.abuseConfidenceScore}%</span>
                                </div>
                            ) : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                        </div>
                        <div style={rowStyle}><span style={{ color: 'var(--text-muted)' }}>Reports</span><span>{data.ipReputation?.totalReports || 0}</span></div>
                    </div>
                </div>

                {/* 7. Safe Browsing */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><ShieldCheck size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Google Safe Browsing</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Threat Check</span>
                            {data.safeBrowsing ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {getStatusIcon(data.safeBrowsing.isSafe ? 'success' : 'danger')}
                                    <span style={{ fontWeight: 600, color: data.safeBrowsing.isSafe ? 'var(--success)' : 'var(--danger)' }}>{data.safeBrowsing.isSafe ? 'CLEAN' : 'THREAT'}</span>
                                </div>
                            ) : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                        </div>
                    </div>
                </div>

                {/* 8. Security Headers */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><FileCheck size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Security Headers</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Grade</span>
                            {data.securityHeaders ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {getStatusIcon(['A', 'B'].includes(data.securityHeaders.grade) ? 'success' : data.securityHeaders.grade === 'C' ? 'warning' : 'danger')}
                                    <span style={{ fontWeight: 600, color: ['A', 'B'].includes(data.securityHeaders.grade) ? 'var(--success)' : data.securityHeaders.grade === 'C' ? 'var(--warning)' : 'var(--danger)' }}>
                                        {data.securityHeaders.grade} ({data.securityHeaders.score}/100)
                                    </span>
                                </div>
                            ) : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                        </div>
                    </div>
                </div>

                {/* 9. Cookie Security */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><Cookie size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Cookie Security</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Status</span>
                            {data.cookieSecurity ? (
                                data.cookieSecurity.totalCookies === 0 ? (
                                    <span style={{ color: 'var(--success)' }}>No cookies</span>
                                ) : (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        {getStatusIcon(data.cookieSecurity.hasIssues ? 'warning' : 'success')}
                                        <span style={{ color: data.cookieSecurity.hasIssues ? 'var(--warning)' : 'var(--success)' }}>
                                            {data.cookieSecurity.secureCookies}/{data.cookieSecurity.totalCookies} secure
                                        </span>
                                    </div>
                                )
                            ) : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                        </div>
                    </div>
                </div>

                {/* 10. Virtual Sandbox */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}><ShieldCheck size={20} color="var(--primary)" /><h3 style={{ fontSize: '1rem' }}>Virtual Sandbox</h3></div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {data.dockerScan ? (
                            data.dockerScan.success ? (
                                <>
                                    {/* Overall Risk Level */}
                                    {data.dockerScan.analysisSummary && (
                                        <div style={rowStyle}>
                                            <span style={{ color: 'var(--text-muted)' }}>Overall Risk</span>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                {getStatusIcon(
                                                    data.dockerScan.analysisSummary.overallRisk === 'safe' ? 'success' :
                                                    data.dockerScan.analysisSummary.overallRisk === 'low' ? 'success' :
                                                    data.dockerScan.analysisSummary.overallRisk === 'medium' ? 'warning' : 'danger'
                                                )}
                                                <span style={{ 
                                                    color: data.dockerScan.analysisSummary.overallRisk === 'safe' ? 'var(--success)' :
                                                           data.dockerScan.analysisSummary.overallRisk === 'low' ? 'var(--success)' :
                                                           data.dockerScan.analysisSummary.overallRisk === 'medium' ? 'var(--warning)' : 'var(--danger)',
                                                    textTransform: 'capitalize',
                                                    fontWeight: 600
                                                }}>
                                                    {data.dockerScan.analysisSummary.overallRisk}
                                                </span>
                                            </div>
                                        </div>
                                    )}
                                    <div style={rowStyle}>
                                        <span style={{ color: 'var(--text-muted)' }}>Network Requests</span>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            {getStatusIcon(data.dockerScan.suspiciousRequests.length > 0 ? 'danger' : 'success')}
                                            <span style={{ color: data.dockerScan.suspiciousRequests.length > 0 ? 'var(--danger)' : 'var(--success)' }}>
                                                {data.dockerScan.suspiciousRequests.length > 0 
                                                    ? `${data.dockerScan.suspiciousRequests.length} suspicious` 
                                                    : `${data.dockerScan.totalRequests} clean`}
                                            </span>
                                        </div>
                                    </div>
                                    {/* Critical/High count breakdown */}
                                    {data.dockerScan.analysisSummary && (data.dockerScan.analysisSummary.criticalCount > 0 || data.dockerScan.analysisSummary.highCount > 0) && (
                                        <div style={rowStyle}>
                                            <span style={{ color: 'var(--text-muted)' }}>Severity</span>
                                            <div style={{ display: 'flex', gap: '12px', fontSize: '0.85rem' }}>
                                                {data.dockerScan.analysisSummary.criticalCount > 0 && (
                                                    <span style={{ color: 'var(--danger)', fontWeight: 600 }}>
                                                        {data.dockerScan.analysisSummary.criticalCount} critical
                                                    </span>
                                                )}
                                                {data.dockerScan.analysisSummary.highCount > 0 && (
                                                    <span style={{ color: '#f97316', fontWeight: 600 }}>
                                                        {data.dockerScan.analysisSummary.highCount} high
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                    {/* Categories detected */}
                                    {data.dockerScan.analysisSummary && Object.keys(data.dockerScan.analysisSummary.categories).length > 0 && (
                                        <div style={{ marginTop: '4px' }}>
                                            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', display: 'block', marginBottom: '6px' }}>Categories Detected</span>
                                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                                {Object.entries(data.dockerScan.analysisSummary.categories).slice(0, 5).map(([category, count]) => (
                                                    <span key={category} style={{
                                                        background: 'rgba(139, 92, 246, 0.15)',
                                                        color: 'var(--primary)',
                                                        padding: '2px 8px',
                                                        borderRadius: '12px',
                                                        fontSize: '0.75rem',
                                                        fontWeight: 500
                                                    }}>
                                                        {category} ({count})
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    <div style={rowStyle}>
                                        <span style={{ color: 'var(--text-muted)' }}>Third-Party Domains</span>
                                        <span>{data.dockerScan.thirdPartyDomains.length}</span>
                                    </div>
                                    {data.dockerScan.pageTitle && (
                                        <div style={rowStyle}>
                                            <span style={{ color: 'var(--text-muted)' }}>Page Title</span>
                                            <span style={{ fontSize: '0.85rem', maxWidth: '60%', textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.dockerScan.pageTitle}</span>
                                        </div>
                                    )}
                                </>
                            ) : (
                                <div style={rowStyle}>
                                    <span style={{ color: 'var(--text-muted)' }}>Status</span>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        {getStatusIcon('warning')}
                                        <span style={{ color: 'var(--warning)' }}>Unavailable</span>
                                    </div>
                                </div>
                            )
                        ) : (
                            <div style={rowStyle}>
                                <span style={{ color: 'var(--text-muted)' }}>Status</span>
                                <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Vulnerabilities Section */}
            {(data.sensitiveFiles?.hasVulnerabilities || data.versionDisclosure?.hasDisclosure || data.adminPanels?.hasExposedPanels) && (
                <div style={{ marginTop: '24px' }}>
                    <h3 style={{ fontSize: '1.2rem', marginBottom: '16px', color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <ShieldAlert size={24} />
                        Vulnerabilities Detected
                    </h3>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {/* Exposed Files */}
                        {data.sensitiveFiles?.hasVulnerabilities && (
                            <div className="glass-card" style={{ padding: '16px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--danger)' }}>
                                <h4 style={{ marginBottom: '12px', color: 'var(--danger)' }}>
                                    🚨 Exposed Sensitive Files ({data.sensitiveFiles.criticalCount} critical, {data.sensitiveFiles.highCount} high)
                                </h4>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    {data.sensitiveFiles.exposedFiles.slice(0, 5).map((file, i) => (
                                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
                                            <code style={{ color: 'var(--primary)' }}>{file.path}</code>
                                            <span style={{
                                                color: file.severity === 'critical' ? 'var(--danger)' :
                                                    file.severity === 'high' ? 'var(--warning)' : 'var(--text-muted)',
                                                textTransform: 'uppercase',
                                                fontSize: '0.8rem'
                                            }}>{file.severity}</span>
                                        </div>
                                    ))}
                                    {data.sensitiveFiles.exposedFiles.length > 5 && (
                                        <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                                            +{data.sensitiveFiles.exposedFiles.length - 5} more...
                                        </span>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Version Disclosure */}
                        {data.versionDisclosure?.hasDisclosure && (
                            <div className="glass-card" style={{ padding: '16px', background: 'rgba(251, 191, 36, 0.1)', border: '1px solid var(--warning)' }}>
                                <h4 style={{ marginBottom: '12px', color: 'var(--warning)' }}>
                                    ⚠️ Version Information Leaked
                                </h4>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.9rem' }}>
                                    {data.versionDisclosure.serverVersion && (
                                        <div>Server: <code>{data.versionDisclosure.serverVersion}</code></div>
                                    )}
                                    {data.versionDisclosure.poweredBy && (
                                        <div>Powered By: <code>{data.versionDisclosure.poweredBy}</code></div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Admin Panels */}
                        {data.adminPanels?.hasExposedPanels && (
                            <div className="glass-card" style={{ padding: '16px', background: 'rgba(251, 191, 36, 0.1)', border: '1px solid var(--warning)' }}>
                                <h4 style={{ marginBottom: '12px', color: 'var(--warning)' }}>
                                    📍 Exposed Endpoints ({data.adminPanels.foundPanels.length} found)
                                </h4>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                    {data.adminPanels.foundPanels.map((panel, i) => (
                                        <span key={i} style={{
                                            background: 'rgba(255,255,255,0.1)',
                                            padding: '4px 8px',
                                            borderRadius: '4px',
                                            fontSize: '0.85rem'
                                        }}>
                                            <code>{panel.path}</code>
                                            <span style={{ color: 'var(--text-muted)', marginLeft: '4px' }}>({panel.type})</span>
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Download Button */}
            <div style={{ marginTop: '32px', textAlign: 'center', display: 'flex', gap: '16px', justifyContent: 'center', flexWrap: 'wrap' }}>
                <button className="neon-button" onClick={handleDownloadPDF} style={{ background: 'rgba(255,255,255,0.05)', color: 'white', border: '1px solid var(--glass-border)', display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                    <Download size={18} />
                    Download PDF Report
                </button>
                <button
                    className="neon-button"
                    onClick={() => setIsChatOpen(true)}
                    style={{
                        background: 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)',
                        color: 'black',
                        border: 'none',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '8px',
                        fontWeight: 600
                    }}
                >
                    <MessageCircle size={18} />
                    Ask AI About Results
                </button>
            </div>

            {/* AI Chat Panel */}
            <ChatPanel
                scanContext={data}
                isOpen={isChatOpen}
                onClose={() => setIsChatOpen(false)}
            />
        </div>
    );
};

export default SecurityReport;
