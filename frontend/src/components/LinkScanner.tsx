import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Loader2, ShieldCheck, AlertCircle } from 'lucide-react';
import SecurityReport from './SecurityReport';

const LinkScanner: React.FC = () => {
    const [url, setUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [reportData, setReportData] = useState<any>(null);

    const handleScan = () => {
        if (!url) return;

        setIsScanning(true);
        setReportData(null);

        // Simulate scanning delay
        setTimeout(() => {
            setIsScanning(false);
            // Mock data for now
            setReportData({
                url: url,
                score: Math.floor(Math.random() * 40) + 60, // 60-99
                domainAge: 'Oct 12, 2018 (6 years ago)',
                sslStatus: 'valid',
                registrar: 'NameCheap, Inc.',
                serverLocation: 'San Francisco, US',
                sandboxResult: 'clean'
            });
        }, 2500);
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            <div className="glass-card" style={{ padding: '40px', textAlign: 'center' }}>
                <h2 style={{ marginBottom: '24px' }}>Deep Scan URL</h2>
                <div style={{ position: 'relative', marginBottom: '24px' }}>
                    <input
                        type="text"
                        className="input-field"
                        placeholder="https://example.com"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                    />
                    <Search
                        style={{ position: 'absolute', right: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
                        size={20}
                    />
                </div>
                <button
                    className="neon-button"
                    onClick={handleScan}
                    disabled={isScanning || !url}
                    style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}
                >
                    {isScanning ? (
                        <>
                            <Loader2 className="animate-spin" size={20} />
                            Analyzing Security Vectors...
                        </>
                    ) : (
                        <>
                            <ShieldCheck size={20} />
                            Initialize Security Scan
                        </>
                    )}
                </button>
            </div>

            <AnimatePresence>
                {isScanning && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        className="glass-card scanning-pulse"
                        style={{ padding: '40px', textAlign: 'center' }}
                    >
                        <Loader2 className="animate-spin" size={48} style={{ color: 'var(--primary)', marginBottom: '20px' }} />
                        <h3>Running Virtual Sandbox...</h3>
                        <p style={{ color: 'var(--text-muted)', marginTop: '8px' }}>Checking for malicious redirections and file drops</p>
                    </motion.div>
                )}

                {reportData && !isScanning && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                    >
                        <SecurityReport data={reportData} />
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default LinkScanner;
