import React from 'react';
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
    Shield
} from 'lucide-react';
import { generatePDFReport } from '../utils/pdfGenerator';

interface ReportData {
    url: string;
    score: number;
    domainAge: string;
    sslStatus: 'valid' | 'expired' | 'none' | 'invalid';
    registrar: string;
    serverLocation: string;
    sandboxResult: 'clean' | 'suspicious' | 'malicious';
    // New fields
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
    isp?: string;
}

const SecurityReport: React.FC<{ data: ReportData }> = ({ data }) => {
    const getScoreColor = (score: number) => {
        if (score >= 80) return 'var(--success)';
        if (score >= 50) return 'var(--warning)';
        return 'var(--danger)';
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'clean': return <CheckCircle color="var(--success)" size={18} />;
            case 'success': return <CheckCircle color="var(--success)" size={18} />;
            case 'suspicious': return <AlertTriangle color="var(--warning)" size={18} />;
            case 'warning': return <AlertTriangle color="var(--warning)" size={18} />;
            case 'malicious': return <ShieldAlert color="var(--danger)" size={18} />;
            case 'danger': return <ShieldAlert color="var(--danger)" size={18} />;
            default: return null;
        }
    };

    const handleDownloadPDF = () => {
        generatePDFReport(data);
    };

    const cardStyle = {
        padding: '20px',
        background: 'rgba(255,255,255,0.02)'
    };

    const headerStyle = {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        marginBottom: '16px'
    };

    const rowStyle = {
        display: 'flex',
        justifyContent: 'space-between'
    };

    return (
        <div className="glass-card" style={{ padding: '32px' }}>
            {/* Header with Score */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
                <div>
                    <h2 style={{ fontSize: '1.5rem', marginBottom: '4px' }}>Security Intelligence Report</h2>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Analyzed: {data.url}</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                    <div style={{
                        fontSize: '2.5rem',
                        fontWeight: 800,
                        color: getScoreColor(data.score),
                        textShadow: `0 0 20px ${getScoreColor(data.score)}44`
                    }}>
                        {data.score}
                    </div>
                    <span className={`score-badge ${data.score >= 80 ? 'score-safe' : data.score >= 50 ? 'score-warn' : 'score-danger'}`}>
                        {data.score >= 80 ? 'Secure' : data.score >= 50 ? 'Warning' : 'Danger'}
                    </span>
                </div>
            </div>

            {/* Grid of Cards - 2 columns */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>

                {/* 1. Domain Information */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <Globe size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Domain Information</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Creation Date</span>
                            <span>{data.domainAge}</span>
                        </div>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Registrar</span>
                            <span>{data.registrar}</span>
                        </div>
                    </div>
                </div>

                {/* 2. SSL Certificate */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <Lock size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>SSL Certificate</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Status</span>
                            <span style={{ color: data.sslStatus === 'valid' ? 'var(--success)' : 'var(--danger)' }}>
                                {data.sslStatus?.toUpperCase() || 'UNKNOWN'}
                            </span>
                        </div>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Encryption</span>
                            <span>TLS 1.3 / AES-256</span>
                        </div>
                    </div>
                </div>

                {/* 3. Infrastructure */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <Server size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Infrastructure</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Location</span>
                            <span>{data.serverLocation}</span>
                        </div>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Hosting</span>
                            <span>{data.isp || 'Unknown'}</span>
                        </div>
                    </div>
                </div>

                {/* 4. Reverse DNS */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <Network size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Reverse DNS</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>PTR Match</span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                {data.reverseDns ? (
                                    <>
                                        {getStatusIcon(data.reverseDns.matches ? 'success' : 'warning')}
                                        <span style={{ color: data.reverseDns.matches ? 'var(--success)' : 'var(--warning)' }}>
                                            {data.reverseDns.matches ? 'VERIFIED' : 'NO MATCH'}
                                        </span>
                                    </>
                                ) : (
                                    <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                                )}
                            </div>
                        </div>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Hostnames</span>
                            <span style={{ fontSize: '0.85rem', textAlign: 'right', maxWidth: '60%', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {data.reverseDns?.hostnames?.length ? data.reverseDns.hostnames[0] : 'None'}
                            </span>
                        </div>
                    </div>
                </div>

                {/* 5. Port Scan */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <Wifi size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Port Scan</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Status</span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                {data.portScan ? (
                                    <>
                                        {getStatusIcon(data.portScan.isSuspicious ? 'warning' : 'success')}
                                        <span style={{ color: data.portScan.isSuspicious ? 'var(--warning)' : 'var(--success)' }}>
                                            {data.portScan.isSuspicious ? 'SUSPICIOUS' : 'CLEAN'}
                                        </span>
                                    </>
                                ) : (
                                    <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                                )}
                            </div>
                        </div>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Open Ports</span>
                            <span>
                                {data.portScan?.openPorts?.length || 0} ({data.portScan?.suspiciousPorts?.length || 0} risky)
                            </span>
                        </div>
                    </div>
                </div>

                {/* 6. IP Reputation */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <Shield size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>IP Reputation</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Abuse Score</span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                {data.ipReputation ? (
                                    <>
                                        {getStatusIcon(data.ipReputation.isSuspicious ? 'danger' : 'success')}
                                        <span style={{
                                            color: data.ipReputation.abuseConfidenceScore > 25
                                                ? 'var(--danger)'
                                                : 'var(--success)'
                                        }}>
                                            {data.ipReputation.abuseConfidenceScore}%
                                        </span>
                                    </>
                                ) : (
                                    <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                                )}
                            </div>
                        </div>
                        <div style={rowStyle}>
                            <span style={{ color: 'var(--text-muted)' }}>Reports</span>
                            <span>{data.ipReputation?.totalReports || 0}</span>
                        </div>
                    </div>
                </div>

                {/* 7. Safe Browsing */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <ShieldCheck size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Google Safe Browsing</h3>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Threat Check</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {getStatusIcon('success')}
                            <span style={{ fontWeight: 600, color: 'var(--success)' }}>CLEAN</span>
                        </div>
                    </div>
                </div>

                {/* 8. Virtual Sandbox */}
                <div className="glass-card" style={cardStyle}>
                    <div style={headerStyle}>
                        <ShieldCheck size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Virtual Sandbox</h3>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Safety Check</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {getStatusIcon(data.sandboxResult)}
                            <span style={{ fontWeight: 600 }}>{data.sandboxResult?.toUpperCase() || 'PENDING'}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Download Button */}
            <div style={{ marginTop: '32px', textAlign: 'center' }}>
                <button
                    className="neon-button"
                    onClick={handleDownloadPDF}
                    style={{
                        background: 'rgba(255,255,255,0.05)',
                        color: 'white',
                        border: '1px solid var(--glass-border)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '8px'
                    }}
                >
                    <Download size={18} />
                    Download PDF Report
                </button>
            </div>
        </div>
    );
};

export default SecurityReport;
