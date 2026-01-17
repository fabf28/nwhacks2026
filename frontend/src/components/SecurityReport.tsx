import React from 'react';
import { motion } from 'framer-motion';
import { CheckCircle, AlertTriangle, ShieldAlert, Globe, Lock, ShieldCheck, Server } from 'lucide-react';

interface ReportData {
    url: string;
    score: number;
    domainAge: string;
    sslStatus: 'valid' | 'expired' | 'none';
    registrar: string;
    serverLocation: string;
    sandboxResult: 'clean' | 'suspicious' | 'malicious';
}

const SecurityReport: React.FC<{ data: ReportData }> = ({ data }) => {
    const getScoreColor = (score: number) => {
        if (score >= 80) return 'var(--success)';
        if (score >= 50) return 'var(--warning)';
        return 'var(--danger)';
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'clean': return <CheckCircle color="var(--success)" />;
            case 'suspicious': return <AlertTriangle color="var(--warning)" />;
            case 'malicious': return <ShieldAlert color="var(--danger)" />;
            default: return null;
        }
    };

    return (
        <div className="glass-card" style={{ padding: '32px' }}>
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

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
                <div className="glass-card" style={{ padding: '20px', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                        <Globe size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Domain Information</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Creation Date</span>
                            <span>{data.domainAge}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Registrar</span>
                            <span>{data.registrar}</span>
                        </div>
                    </div>
                </div>

                <div className="glass-card" style={{ padding: '20px', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                        <Lock size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>SSL Certificate</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Status</span>
                            <span style={{ color: data.sslStatus === 'valid' ? 'var(--success)' : 'var(--danger)' }}>
                                {data.sslStatus.toUpperCase()}
                            </span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Encryption</span>
                            <span>TLS 1.3 / AES-256</span>
                        </div>
                    </div>
                </div>

                <div className="glass-card" style={{ padding: '20px', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                        <Server size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Infrastructure</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Location</span>
                            <span>{data.serverLocation}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Hosting</span>
                            <span>Cloudflare, Inc.</span>
                        </div>
                    </div>
                </div>

                <div className="glass-card" style={{ padding: '20px', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                        <ShieldCheck size={20} color="var(--primary)" />
                        <h3 style={{ fontSize: '1rem' }}>Virtual Sandbox</h3>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Safety Check</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {getStatusIcon(data.sandboxResult)}
                            <span style={{ fontWeight: 600 }}>{data.sandboxResult.toUpperCase()}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div style={{ marginTop: '32px', textAlign: 'center' }}>
                <button className="neon-button" style={{ background: 'rgba(255,255,255,0.05)', color: 'white', border: '1px solid var(--glass-border)' }}>
                    Download PDF Report
                </button>
            </div>
        </div>
    );
};

export default SecurityReport;
