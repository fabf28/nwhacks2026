import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowRight, CheckCircle, Globe, Lock, Server, Network, Wifi, Shield, ShieldCheck, FileCheck, Cookie, Info } from 'lucide-react';
import { io, Socket } from 'socket.io-client';

interface ProgressUpdate {
    step: string;
    message: string;
    status: 'pending' | 'success' | 'warning' | 'error';
    data?: any;
}

interface WebsiteScannerProps {
    initialUrl?: string | null;
}

type ScanStage = 'input' | 'detecting' | 'scanning' | 'verdict' | 'report';

// Predefined scanning steps with loading and result states
const SCANNING_STEPS = [
    { id: 'geo', loading: 'Geolocating server...', result: 'Server location verified', color: 'var(--success-green)' },
    { id: 'redirects', loading: 'Looking for hidden redirects...', result: 'No hidden redirects found', color: 'var(--success-green)' },
    { id: 'ssl', loading: 'Checking SSL certificate...', result: 'Valid SSL certificate detected', color: 'var(--success-green)' },
    { id: 'ports', loading: 'Scanning for open ports...', result: 'Port scan completed', color: 'var(--success-green)' },
    { id: 'headers', loading: 'Analyzing security headers...', result: 'Headers analyzed', color: 'var(--success-green)' },
    { id: 'reputation', loading: 'Checking IP reputation...', result: 'IP check completed', color: 'var(--success-green)' },
    { id: 'sandbox', loading: 'Running sandbox analysis...', result: 'Sandbox analysis finished', color: 'var(--success-green)' },
    { id: 'age', loading: 'Verifying domain age...', result: 'Domain age verified', color: 'var(--success-green)' },
    { id: 'cookies', loading: 'Checking cookie security...', result: 'Cookie scan complete', color: 'var(--success-green)' },
    { id: 'threat', loading: 'Final threat assessment...', result: 'Assessment complete', color: 'var(--success-green)' }
];

const ITEM_EXPLANATIONS: Record<string, string> = {
    'Created': "How long this website has existed. Older domains are generally more trustworthy.",
    'Registrar': "The company that manages this domain name.",
    'Status': "Whether the website provides a secure, encrypted connection to protect your data.",
    'TLS Version': "The version of the security protocol used. Newer versions (1.2+) are more secure.",
    'Cipher Strength': "How hard the encryption is to break. Stronger is better.",
    'Location': "The physical country/city where the website's server is located.",
    'Hosting': "The company hosting the website's server.",
    'PTR Match': "Verifies if the server's IP address matches its domain name, a sign of legitimacy.",
    'Open Ports': "Checks for open 'doors' on the server that hackers could use to enter.",
    'Abuse Score': "A score based on whether this server has been reported for malicious activity before.",
    'Total Reports': "Number of times this IP address has been reported for abuse.",
    'Threat Check': "Checks if Google has flagged this site as dangerous or deceptive.",
    'X-Frame-Options': "Prevents your browser from being tricked into clicking invisible buttons (Clickjacking).",
    'Content-Security-Policy': "Controls which resources the browser is allowed to load for this page.",
    'HSTS': "Forces the browser to use a secure (HTTPS) connection.",
    'Secure Flag': "Ensures cookies are only sent over secure encrypted connections.",
    'HttpOnly Flag': "Prevents malicious scripts from accessing your private cookies.",
    'Sensitive Files': "Checks if private files (like configuration files) are accidentally exposed.",
    'Version Disclosure': "Checks if the server reveals its software version, which can help attackers.",
    'Admin Panels': "Checks if administrative login pages are publicly accessible.",
    'Network Requests': "The number of outgoing connections this website makes. Suspicious sites often connect to known malware servers.",
    'Third-Party Domains': "External websites this site contacts. A high number could indicate tracking or malicious redirectors."
};

const ReportItemTooltip: React.FC<{ text: string }> = ({ text }) => (
    <div className="tooltip-content">
        {text}
        <div className="tooltip-arrow"></div>
    </div>
);

const ReportRow: React.FC<{ label: string; value: React.ReactNode; color?: string }> = ({ label, value, color }) => {
    const explanation = ITEM_EXPLANATIONS[label];

    return (
        <div className="report-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', alignItems: 'center' }}>
            <span
                className={`report-label ${explanation ? 'tooltip-trigger' : ''}`}
                style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
            >
                {label}
                {explanation && <Info size={12} style={{ opacity: 0.5 }} />}
                {explanation && <ReportItemTooltip text={explanation} />}
            </span>
            <span className="report-value" style={{ color: color || 'var(--text-main)', textAlign: 'right' }}>{value}</span>
        </div>
    );
};

const WebsiteScanner: React.FC<WebsiteScannerProps> = ({ initialUrl }) => {
    const [url, setUrl] = useState('');
    const [stage, setStage] = useState<ScanStage>('input');
    const [progressUpdates, setProgressUpdates] = useState<ProgressUpdate[]>([]);
    const [reportData, setReportData] = useState<any>(null);
    const [activeStepIndex, setActiveStepIndex] = useState(-1);
    const [completedSteps, setCompletedSteps] = useState<number[]>([]);
    const socketRef = useRef<Socket | null>(null);
    const hasAutoScanned = useRef(false);

    useEffect(() => {
        const socket = io('http://localhost:3001');
        socketRef.current = socket;

        socket.on('connect', () => {
            console.log('Connected to backend');
        });

        socket.on('scan-progress', (update: ProgressUpdate) => {
            setProgressUpdates((prev) => [...prev, update]);

            if (update.step === 'complete' && update.data) {
                const result = update.data;
                setReportData({
                    url: result.url,
                    score: result.score,
                    domainAge: result.checks?.whois?.createdDate || 'Unknown',
                    sslStatus: result.checks?.ssl?.valid ? 'valid' : 'invalid',
                    registrar: result.checks?.whois?.registrar || 'Unknown',
                    serverLocation: result.checks?.geolocation
                        ? `${result.checks.geolocation.city}, ${result.checks.geolocation.country}`
                        : 'Unknown',
                    isp: result.checks?.geolocation?.isp || 'Unknown',
                    // SSL/TLS details
                    ssl: result.checks?.ssl ? {
                        tlsVersion: result.checks.ssl.tlsVersion,
                        cipher: result.checks.ssl.cipher,
                        cipherStrength: result.checks.ssl.cipherStrength,
                        certificateChain: result.checks.ssl.certificateChain,
                    } : undefined,
                    // Network infrastructure data
                    reverseDns: result.checks?.reverseDns,
                    portScan: result.checks?.portScan,
                    ipReputation: result.checks?.ipReputation,
                    // Threat intelligence
                    safeBrowsing: result.checks?.safeBrowsing,
                    // HTTP Security
                    securityHeaders: result.checks?.securityHeaders,
                    cookieSecurity: result.checks?.cookieSecurity,
                    // Vulnerability data
                    sensitiveFiles: result.checks?.sensitiveFiles,
                    versionDisclosure: result.checks?.versionDisclosure,
                    adminPanels: result.checks?.adminPanels,
                    // Docker sandbox data
                    dockerScan: result.checks?.dockerScan,
                    checks: result.checks,
                });

                // Wait for all steps to display before showing verdict
                setTimeout(() => {
                    setStage('verdict');
                }, 1000);
            }
        });

        socket.on('scan-error', (error) => {
            console.error('Scan error:', error);
            setProgressUpdates((prev) => [...prev, {
                step: 'error',
                message: error?.message || 'An error occurred during the scan',
                status: 'error'
            }]);
        });

        return () => {
            socket.disconnect();
        };
    }, []);

    // Auto-scan when initialUrl is provided
    useEffect(() => {
        if (initialUrl && !hasAutoScanned.current && socketRef.current) {
            hasAutoScanned.current = true;
            setUrl(initialUrl);
            startScan(initialUrl);
        }
    }, [initialUrl]);

    const normalizeUrl = (inputUrl: string): string => {
        let normalized = inputUrl.trim();
        if (!normalized.match(/^https?:\/\//i)) {
            normalized = 'https://' + normalized;
        }
        return normalized;
    };

    const startScan = (urlToScan: string) => {
        const normalizedUrl = normalizeUrl(urlToScan);
        setUrl(normalizedUrl);
        setProgressUpdates([]);
        setCompletedSteps([]);
        setActiveStepIndex(0);
        setStage('detecting');

        // Show "Website Detected" for 2 seconds
        setTimeout(() => {
            setStage('scanning');
            socketRef.current?.emit('start-scan', { url: normalizedUrl });
        }, 2000);
    };

    const handleSubmit = () => {
        if (!url) return;
        startScan(url);
    };

    // Simulate scanning animation with 1s delays
    useEffect(() => {
        if (stage === 'scanning') {
            const interval = setInterval(() => {
                setActiveStepIndex((prevIndex) => {
                    // Mark current as complete
                    setCompletedSteps(prev => [...prev, prevIndex]);

                    // Move to next
                    const nextIndex = prevIndex + 1;
                    if (nextIndex >= SCANNING_STEPS.length) {
                        clearInterval(interval);
                        // Only switch to verdict if we have data
                        if (reportData) {
                            setTimeout(() => setStage('verdict'), 500);
                        }
                        return prevIndex;
                    }
                    return nextIndex;
                });
            }, 1000);

            return () => clearInterval(interval);
        }
    }, [stage, reportData]);

    // Watch for report data to ensure we transition eventually if animation finishes early
    useEffect(() => {
        if (reportData && completedSteps.length >= SCANNING_STEPS.length) {
            setTimeout(() => setStage('verdict'), 500);
        }
    }, [reportData, completedSteps]);

    const calculateMaliciousPercentage = (score: number) => {
        // Convert score (0-100 where 100 is safe) to malicious percentage
        return Math.max(0, Math.min(100, 100 - score));
    };

    const getVerdictColor = (score: number) => {
        const maliciousPercent = calculateMaliciousPercentage(score);
        if (maliciousPercent < 40) return { color: 'var(--success-green)', glow: 'var(--glow-green)' };
        if (maliciousPercent < 60) return { color: 'var(--warning-gold)', glow: 'var(--glow-gold)' };
        return { color: 'var(--danger-red)', glow: 'var(--glow-red)' };
    };

    const getVerdictMessage = (score: number) => {
        const maliciousPercent = calculateMaliciousPercentage(score);
        if (maliciousPercent < 40) return "This website doesn't seem malicious";
        if (maliciousPercent < 60) return "This website seems a bit suspicious";
        return "This website is likely to be malicious";
    };

    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            minHeight: '800px',
            padding: '40px 20px',
            justifyContent: 'center'
        }}>
            {/* Logo */}
            <motion.h1
                className="neon-text-pink"
                style={{
                    fontSize: '32px',
                    textAlign: 'center',
                    marginBottom: '40px',
                    textTransform: 'uppercase'
                }}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
            >
                SAFESITE
            </motion.h1>

            <AnimatePresence mode="wait">
                {/* Input Stage */}
                {stage === 'input' && (
                    <motion.div
                        key="input"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        style={{ textAlign: 'center' }}
                    >
                        <div style={{
                            position: 'relative',
                            marginBottom: '24px'
                        }}>
                            <input
                                type="text"
                                className="input-field"
                                placeholder="Enter a website"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                                style={{ paddingRight: '50px' }}
                            />
                            <button
                                onClick={handleSubmit}
                                disabled={!url}
                                style={{
                                    position: 'absolute',
                                    right: '12px',
                                    top: '50%',
                                    transform: 'translateY(-50%)',
                                    background: 'none',
                                    border: 'none',
                                    cursor: url ? 'pointer' : 'not-allowed',
                                    opacity: url ? 1 : 0.3,
                                    transition: 'all 0.3s ease'
                                }}
                            >
                                <ArrowRight size={24} color="var(--text-lavender)" />
                            </button>
                        </div>
                    </motion.div>
                )}

                {/* Website Detected Stage */}
                {stage === 'detecting' && (
                    <motion.div
                        key="detecting"
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.9 }}
                        style={{ textAlign: 'center' }}
                    >
                        <motion.div
                            animate={{ scale: [1, 1.05, 1] }}
                            transition={{ duration: 1.5, repeat: Infinity }}
                        >
                            <p style={{
                                fontSize: '18px',
                                color: 'var(--text-main)',
                                fontWeight: 600
                            }}>
                                Website Detected
                            </p>
                            <p style={{
                                fontSize: '14px',
                                color: 'var(--text-muted)',
                                marginTop: '8px'
                            }}>
                                {url}
                            </p>
                        </motion.div>
                    </motion.div>
                )}

                {/* Scanning Stage */}
                {stage === 'scanning' && (
                    <motion.div
                        key="scanning"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        style={{
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '16px'
                        }}
                    >
                        <p style={{
                            fontSize: '14px',
                            color: 'var(--text-muted)',
                            textAlign: 'center',
                            marginBottom: '16px'
                        }}>
                            Running security checks...
                        </p>

                        {SCANNING_STEPS.map((step, index) => {
                            const isCompleted = completedSteps.includes(index);
                            const isActive = index === activeStepIndex;

                            if (!isCompleted && !isActive) return null;

                            return (
                                <motion.div
                                    key={step.id}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ duration: 0.3 }}
                                    className="loading-check"
                                    style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px',
                                        padding: '12px 16px',
                                        background: 'rgba(255, 255, 255, 0.05)',
                                        borderRadius: '12px',
                                        border: '1px solid rgba(255, 255, 255, 0.1)'
                                    }}
                                >
                                    {isActive ? (
                                        <div className="loading-spinner" />
                                    ) : (
                                        <CheckCircle size={20} color={step.color} />
                                    )}
                                    <span style={{
                                        color: isActive ? 'var(--text-main)' : step.color,
                                        fontSize: '14px',
                                        fontWeight: isActive ? 400 : 500
                                    }}>
                                        {isActive ? step.loading : step.result}
                                    </span>
                                </motion.div>
                            );
                        })}
                    </motion.div>
                )}

                {/* Verdict Stage */}
                {stage === 'verdict' && reportData && (
                    <motion.div
                        key="verdict"
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0 }}
                        style={{ textAlign: 'center' }}
                    >
                        <p style={{
                            fontSize: '14px',
                            color: 'var(--text-muted)',
                            marginBottom: '8px'
                        }}>
                            {reportData.url}
                        </p>

                        <div
                            className="verdict-card"
                            style={{
                                marginTop: '24px',
                                marginBottom: '32px',
                                background: `linear-gradient(135deg, ${getVerdictColor(reportData.score).color}20 0%, ${getVerdictColor(reportData.score).color}05 100%)`,
                                border: `2px solid ${getVerdictColor(reportData.score).color}`,
                                boxShadow: getVerdictColor(reportData.score).glow
                            }}
                        >
                            <p style={{
                                fontSize: '12px',
                                color: 'var(--text-muted)',
                                textTransform: 'uppercase',
                                letterSpacing: '1.5px',
                                marginBottom: '8px'
                            }}>
                                🚨 Risk Detected
                            </p>

                            <p style={{
                                fontSize: '14px',
                                color: 'var(--text-main)',
                                marginBottom: '8px'
                            }}>
                                And the verdict is...
                            </p>

                            <div
                                className="verdict-percentage"
                                style={{
                                    color: getVerdictColor(reportData.score).color,
                                    textShadow: getVerdictColor(reportData.score).glow
                                }}
                            >
                                {calculateMaliciousPercentage(reportData.score)}%
                            </div>

                            <p style={{
                                fontSize: '14px',
                                color: 'var(--text-main)',
                                marginTop: '12px'
                            }}>
                                {getVerdictMessage(reportData.score)}
                            </p>
                        </div>

                        <button
                            className="primary-button"
                            onClick={() => setStage('report')}
                        >
                            View Full Report
                        </button>
                    </motion.div>
                )}

                {/* Full Report Stage - Scrollable with all metrics */}
                {stage === 'report' && reportData && (
                    <motion.div
                        key="report"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        style={{
                            maxHeight: '700px',
                            overflowY: 'auto',
                            paddingRight: '8px'
                        }}
                    >
                        <h2 style={{
                            fontSize: '16px',
                            textTransform: 'uppercase',
                            letterSpacing: '1.5px',
                            marginBottom: '24px',
                            textAlign: 'center'
                        }}>
                            Security Intelligence Report
                        </h2>

                        <p style={{
                            fontSize: '14px',
                            color: 'var(--text-muted)',
                            textAlign: 'center',
                            marginBottom: '32px'
                        }}>
                            {reportData.url}
                        </p>

                        {/* Domain Information */}
                        <div className="report-section">
                            <h3><Globe size={16} style={{ display: 'inline', marginRight: '8px' }} />Domain Information</h3>
                            <div className="glass-card" style={{ padding: '16px' }}>
                                <ReportRow label="Created" value={reportData.domainAge} />
                                <ReportRow label="Registrar" value={reportData.registrar} />
                            </div>
                        </div>

                        {/* SSL/TLS Certificate */}
                        <div className="report-section">
                            <h3><Lock size={16} style={{ display: 'inline', marginRight: '8px' }} />SSL/TLS Certificate</h3>
                            <div className="glass-card" style={{ padding: '16px' }}>
                                <ReportRow
                                    label="Status"
                                    value={reportData.sslStatus?.toUpperCase()}
                                    color={reportData.sslStatus === 'valid' ? 'var(--success-green)' : 'var(--danger-red)'}
                                />
                                {reportData.ssl && (
                                    <>
                                        <ReportRow label="TLS Version" value={reportData.ssl.tlsVersion} />
                                        <ReportRow
                                            label="Cipher Strength"
                                            value={reportData.ssl.cipherStrength?.toUpperCase()}
                                            color={reportData.ssl.cipherStrength === 'strong' ? 'var(--success-green)' :
                                                reportData.ssl.cipherStrength === 'moderate' ? 'var(--warning-gold)' : 'var(--danger-red)'}
                                        />
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Infrastructure */}
                        <div className="report-section">
                            <h3><Server size={16} style={{ display: 'inline', marginRight: '8px' }} />Infrastructure</h3>
                            <div className="glass-card" style={{ padding: '16px' }}>
                                <ReportRow label="Location" value={reportData.serverLocation} />
                                <ReportRow label="Hosting" value={reportData.isp} />
                            </div>
                        </div>

                        {/* Reverse DNS */}
                        {reportData.reverseDns && (
                            <div className="report-section">
                                <h3><Network size={16} style={{ display: 'inline', marginRight: '8px' }} />Reverse DNS</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    <ReportRow
                                        label="PTR Match"
                                        value={reportData.reverseDns.matches ? 'VERIFIED' : 'NO MATCH'}
                                        color={reportData.reverseDns.matches ? 'var(--success-green)' : 'var(--warning-gold)'}
                                    />
                                </div>
                            </div>
                        )}

                        {/* Port Scan */}
                        {reportData.portScan && (
                            <div className="report-section">
                                <h3><Wifi size={16} style={{ display: 'inline', marginRight: '8px' }} />Port Scan</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    <ReportRow
                                        label="Status"
                                        value={reportData.portScan.isSuspicious ? 'SUSPICIOUS' : 'CLEAN'}
                                        color={reportData.portScan.isSuspicious ? 'var(--warning-gold)' : 'var(--success-green)'}
                                    />
                                    {reportData.portScan.openPorts && (
                                        <ReportRow label="Open Ports" value={reportData.portScan.openPorts.join(', ')} />
                                    )}
                                </div>
                            </div>
                        )}

                        {/* IP Reputation */}
                        {reportData.ipReputation && (
                            <div className="report-section">
                                <h3><Shield size={16} style={{ display: 'inline', marginRight: '8px' }} />IP Reputation</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    <ReportRow
                                        label="Abuse Score"
                                        value={`${reportData.ipReputation.abuseConfidenceScore}%`}
                                        color={reportData.ipReputation.abuseConfidenceScore > 25 ? 'var(--danger-red)' : 'var(--success-green)'}
                                    />
                                    <ReportRow label="Total Reports" value={reportData.ipReputation.totalReports} />
                                </div>
                            </div>
                        )}

                        {/* Google Safe Browsing */}
                        {reportData.safeBrowsing && (
                            <div className="report-section">
                                <h3><ShieldCheck size={16} style={{ display: 'inline', marginRight: '8px' }} />Google Safe Browsing</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    <ReportRow
                                        label="Threat Check"
                                        value={reportData.safeBrowsing.isSafe ? 'CLEAN' : 'THREAT'}
                                        color={reportData.safeBrowsing.isSafe ? 'var(--success-green)' : 'var(--danger-red)'}
                                    />
                                </div>
                            </div>
                        )}

                        {/* Security Headers */}
                        {reportData.securityHeaders && (
                            <div className="report-section">
                                <h3><FileCheck size={16} style={{ display: 'inline', marginRight: '8px' }} />Security Headers</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    <ReportRow
                                        label="Grade"
                                        value={`${reportData.securityHeaders.grade} (${reportData.securityHeaders.score}/100)`}
                                        color={['A', 'B'].includes(reportData.securityHeaders.grade) ? 'var(--success-green)' :
                                            reportData.securityHeaders.grade === 'C' ? 'var(--warning-gold)' : 'var(--danger-red)'}
                                    />
                                </div>
                            </div>
                        )}

                        {/* Cookie Security */}
                        {reportData.cookieSecurity && (
                            <div className="report-section">
                                <h3><Cookie size={16} style={{ display: 'inline', marginRight: '8px' }} />Cookie Security</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    <ReportRow
                                        label="Status"
                                        value={reportData.cookieSecurity.totalCookies === 0 ? 'No cookies' :
                                            `${reportData.cookieSecurity.secureCookies}/${reportData.cookieSecurity.totalCookies} secure`}
                                        color={reportData.cookieSecurity.hasIssues ? 'var(--warning-gold)' : 'var(--success-green)'}
                                    />
                                </div>
                            </div>
                        )}

                        {/* Docker Sandbox */}
                        {reportData.dockerScan && (
                            <div className="report-section">
                                <h3><ShieldCheck size={16} style={{ display: 'inline', marginRight: '8px' }} />Virtual Sandbox</h3>
                                <div className="glass-card" style={{ padding: '16px' }}>
                                    {reportData.dockerScan.success ? (
                                        <>
                                            <ReportRow
                                                label="Network Requests"
                                                value={reportData.dockerScan.suspiciousRequests.length > 0
                                                    ? `${reportData.dockerScan.suspiciousRequests.length} suspicious`
                                                    : `${reportData.dockerScan.totalRequests} clean`}
                                                color={reportData.dockerScan.suspiciousRequests.length > 0 ? 'var(--danger-red)' : 'var(--success-green)'}
                                            />
                                            <ReportRow label="Third-Party Domains" value={reportData.dockerScan.thirdPartyDomains.length} />
                                        </>
                                    ) : (
                                        <ReportRow label="Status" value="Unavailable" color="var(--warning-gold)" />
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Vulnerabilities Section */}
                        {(reportData.sensitiveFiles?.hasVulnerabilities ||
                            reportData.versionDisclosure?.hasDisclosure ||
                            reportData.adminPanels?.hasExposedPanels) && (
                                <div className="report-section">
                                    <h3 style={{ color: 'var(--danger-red)' }}>🚨 Vulnerabilities Detected</h3>

                                    {reportData.sensitiveFiles?.hasVulnerabilities && (
                                        <div className="glass-card" style={{
                                            padding: '16px',
                                            background: 'rgba(255, 77, 109, 0.1)',
                                            border: '1px solid var(--danger-red)',
                                            marginBottom: '12px'
                                        }}>
                                            <h4 style={{ fontSize: '14px', marginBottom: '12px', color: 'var(--danger-red)' }}>
                                                Exposed Sensitive Files ({reportData.sensitiveFiles.criticalCount} critical, {reportData.sensitiveFiles.highCount} high)
                                            </h4>
                                            {reportData.sensitiveFiles.exposedFiles.slice(0, 3).map((file: any, i: number) => (
                                                <div key={i} style={{ fontSize: '12px', marginBottom: '6px' }}>
                                                    <code style={{ color: 'var(--primary-neon-pink)' }}>{file.path}</code>
                                                    <span style={{
                                                        marginLeft: '8px',
                                                        color: file.severity === 'critical' ? 'var(--danger-red)' : 'var(--warning-gold)',
                                                        textTransform: 'uppercase',
                                                        fontSize: '10px'
                                                    }}>
                                                        {file.severity}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    {reportData.versionDisclosure?.hasDisclosure && (
                                        <div className="glass-card" style={{
                                            padding: '16px',
                                            background: 'rgba(255, 215, 0, 0.1)',
                                            border: '1px solid var(--warning-gold)',
                                            marginBottom: '12px'
                                        }}>
                                            <h4 style={{ fontSize: '14px', marginBottom: '8px', color: 'var(--warning-gold)' }}>
                                                ⚠️ Version Information Leaked
                                            </h4>
                                            {reportData.versionDisclosure.serverVersion && (
                                                <div style={{ fontSize: '12px' }}>Server: <code>{reportData.versionDisclosure.serverVersion}</code></div>
                                            )}
                                        </div>
                                    )}

                                    {reportData.adminPanels?.hasExposedPanels && (
                                        <div className="glass-card" style={{
                                            padding: '16px',
                                            background: 'rgba(255, 215, 0, 0.1)',
                                            border: '1px solid var(--warning-gold)'
                                        }}>
                                            <h4 style={{ fontSize: '14px', marginBottom: '8px', color: 'var(--warning-gold)' }}>
                                                📍 Exposed Endpoints ({reportData.adminPanels.foundPanels.length} found)
                                            </h4>
                                            {reportData.adminPanels.foundPanels.map((panel: any, i: number) => (
                                                <div key={i} style={{ fontSize: '12px', marginBottom: '4px' }}>
                                                    <code>{panel.path}</code> <span style={{ color: 'var(--text-muted)' }}>({panel.type})</span>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                        <button
                            className="primary-button"
                            onClick={() => {
                                setStage('input');
                                setUrl('');
                                setReportData(null);
                                setProgressUpdates([]);
                                setCompletedSteps([]);
                                setActiveStepIndex(0);
                            }}
                            style={{ marginTop: '24px' }}
                        >
                            Scan Another Website
                        </button>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default WebsiteScanner;
