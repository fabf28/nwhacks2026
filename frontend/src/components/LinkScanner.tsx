import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Loader2, ShieldCheck, CheckCircle, AlertTriangle, XCircle, QrCode } from 'lucide-react';
import { io, Socket } from 'socket.io-client';
import SecurityReport from './SecurityReport';

interface ProgressUpdate {
    step: string;
    message: string;
    status: 'pending' | 'success' | 'warning' | 'error';
    data?: any;
}

interface LinkScannerProps {
    initialUrl?: string | null;
    onScanComplete?: () => void;
}

const LinkScanner: React.FC<LinkScannerProps> = ({ initialUrl, onScanComplete }) => {
    const [url, setUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [isConnected, setIsConnected] = useState(false);
    const [progressUpdates, setProgressUpdates] = useState<ProgressUpdate[]>([]);
    const [reportData, setReportData] = useState<any>(null);
    const [isFromQR, setIsFromQR] = useState(false);
    const socketRef = useRef<Socket | null>(null);
    const hasAutoScanned = useRef(false);

    useEffect(() => {
        // Connect to backend
        const socket = io('http://localhost:3001');
        socketRef.current = socket;

        socket.on('connect', () => {
            console.log('Connected to backend');
            setIsConnected(true);
        });

        socket.on('disconnect', () => {
            setIsConnected(false);
        });

        socket.on('scan-progress', (update: ProgressUpdate) => {
            setProgressUpdates((prev) => [...prev, update]);

            // If scan is complete, extract the report data
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
                    sandboxResult: 'clean',
                });
                setIsScanning(false);
                onScanComplete?.();
            }
        });

        socket.on('scan-error', (error) => {
            console.error('Scan error:', error);
            setIsScanning(false);
        });

        return () => {
            socket.disconnect();
        };
    }, [onScanComplete]);

    // Auto-scan when initialUrl is provided AND socket is connected
    useEffect(() => {
        if (initialUrl && isConnected && !hasAutoScanned.current && socketRef.current) {
            hasAutoScanned.current = true;
            setUrl(initialUrl);
            setIsFromQR(true);
            setIsScanning(true);
            setReportData(null);
            setProgressUpdates([]);
            socketRef.current.emit('start-scan', { url: initialUrl });
        }
    }, [initialUrl, isConnected]);

    const handleScan = () => {
        if (!url || !socketRef.current) return;

        hasAutoScanned.current = false;
        setIsFromQR(false);
        setIsScanning(true);
        setReportData(null);
        setProgressUpdates([]);

        socketRef.current.emit('start-scan', { url });
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'success':
                return <CheckCircle size={16} color="var(--success)" />;
            case 'warning':
                return <AlertTriangle size={16} color="var(--warning)" />;
            case 'error':
                return <XCircle size={16} color="var(--danger)" />;
            default:
                return <Loader2 size={16} className="animate-spin" style={{ color: 'var(--primary)' }} />;
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            {/* QR Source Banner */}
            {isFromQR && isScanning && (
                <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="glass-card"
                    style={{
                        padding: '16px 24px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        background: 'rgba(0, 242, 254, 0.1)',
                        borderColor: 'var(--primary)'
                    }}
                >
                    <QrCode size={20} color="var(--primary)" />
                    <span>Scanning URL from QR Code...</span>
                </motion.div>
            )}

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
                {isScanning && progressUpdates.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        className="glass-card"
                        style={{ padding: '24px' }}
                    >
                        <h3 style={{ marginBottom: '16px' }}>Scan Progress</h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            {progressUpdates.map((update, index) => (
                                <motion.div
                                    key={index}
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    style={{ display: 'flex', alignItems: 'center', gap: '12px' }}
                                >
                                    {getStatusIcon(update.status)}
                                    <span style={{ color: update.status === 'pending' ? 'var(--text-muted)' : 'var(--text-main)' }}>
                                        {update.message}
                                    </span>
                                </motion.div>
                            ))}
                        </div>
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
