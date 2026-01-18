import React, { useEffect, useRef, useState } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import { Camera, CameraOff, AlertCircle } from 'lucide-react';
import { motion } from 'framer-motion';

interface QRScannerProps {
    onScanSuccess: (decodedText: string) => void;
}

const QRScanner: React.FC<QRScannerProps> = ({ onScanSuccess }) => {
    const [scannerStarted, setScannerStarted] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [scannedUrl, setScannedUrl] = useState<string | null>(null);
    const scannerRef = useRef<Html5Qrcode | null>(null);
    const stoppingRef = useRef(false);
    const hasInitializedRef = useRef(false); // Guard against double mount

    useEffect(() => {
        // Guard against React Strict Mode double mount
        if (hasInitializedRef.current) return;
        hasInitializedRef.current = true;

        // Auto-start scanner when component mounts
        startScanner();

        return () => {
            const scanner = scannerRef.current;
            if (scanner && !stoppingRef.current) {
                try {
                    if (scanner.isScanning) {
                        stoppingRef.current = true;
                        scanner.stop().catch(() => { });
                    }
                } catch (e) {
                    // Ignore cleanup errors
                }
            }
            // Reset for potential remount
            hasInitializedRef.current = false;
        };
    }, []);

    const startScanner = async () => {
        // Prevent starting if already running
        if (scannerRef.current) {
            console.log('[QR] Scanner already exists, skipping');
            return;
        }

        setError(null);
        stoppingRef.current = false;

        const scanner = new Html5Qrcode("qr-reader-mobile");
        scannerRef.current = scanner;

        try {
            await scanner.start(
                { facingMode: "environment" },
                { fps: 10, qrbox: { width: 250, height: 250 } },
                async (decodedText) => {
                    if (stoppingRef.current) return;
                    stoppingRef.current = true;

                    console.log('[QR] Code detected:', decodedText);

                    // Show the scanned URL briefly before transitioning
                    setScannedUrl(decodedText);

                    // Stop the scanner immediately
                    try {
                        if (scanner.isScanning) {
                            console.log('[QR] Stopping scanner...');
                            await scanner.stop();
                            console.log('[QR] Scanner stopped');
                        }
                    } catch (e) {
                        console.error('[QR] Error stopping scanner:', e);
                    }

                    // Clear the video element
                    const videoContainer = document.getElementById('qr-reader-mobile');
                    if (videoContainer) {
                        videoContainer.innerHTML = '';
                    }

                    scannerRef.current = null;
                    setScannerStarted(false);

                    // Delay callback to show the URL
                    setTimeout(() => {
                        onScanSuccess(decodedText);
                    }, 1500);
                },
                () => { } // ignore parse errors
            );
            setScannerStarted(true);
        } catch (err) {
            console.error('[QR] Camera error:', err);
            setError("Failed to access camera. Please grant camera permissions.");
        }
    };

    const stopScanner = async () => {
        const scanner = scannerRef.current;
        if (scanner && !stoppingRef.current) {
            stoppingRef.current = true;
            try {
                if (scanner.isScanning) {
                    await scanner.stop();
                }
            } catch (e) {
                // Ignore
            }
            scannerRef.current = null;
            setScannerStarted(false);
        }
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

            {/* Camera View */}
            <div style={{
                width: '100%',
                borderRadius: '20px',
                overflow: 'hidden',
                background: 'rgba(0,0,0,0.6)',
                minHeight: '400px',
                border: scannerStarted ? '2px solid var(--primary-neon-pink)' : '2px dashed var(--glass-border)',
                position: 'relative',
                marginBottom: '24px'
            }}>
                <div id="qr-reader-mobile" style={{ width: '100%', height: '100%' }}></div>

                {!scannerStarted && (
                    <div style={{
                        position: 'absolute',
                        top: 0, left: 0, right: 0, bottom: 0,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        pointerEvents: 'none'
                    }}>
                        {error ? (
                            <div style={{ color: 'var(--danger-red)', textAlign: 'center', padding: '20px' }}>
                                <AlertCircle size={48} style={{ marginBottom: '16px' }} />
                                <p style={{ fontSize: '14px' }}>{error}</p>
                            </div>
                        ) : (
                            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                                <Camera size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                                <p style={{ fontSize: '14px' }}>Camera standby</p>
                            </div>
                        )}
                    </div>
                )}

                {/* Scanned URL Overlay */}
                {scannedUrl && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        style={{
                            position: 'absolute',
                            bottom: '20px',
                            left: '20px',
                            right: '20px',
                            background: 'linear-gradient(135deg, rgba(255, 215, 0, 0.9) 0%, rgba(255, 201, 71, 0.9) 100%)',
                            padding: '16px',
                            borderRadius: '12px',
                            textAlign: 'center',
                            boxShadow: 'var(--glow-gold)'
                        }}
                    >
                        <p style={{
                            fontSize: '14px',
                            fontWeight: 700,
                            color: 'var(--bg-midnight)',
                            wordBreak: 'break-all'
                        }}>
                            {scannedUrl}
                        </p>
                    </motion.div>
                )}
            </div>

            {/* Control Buttons */}
            <div style={{ display: 'flex', gap: '12px' }}>
                {!scannerStarted ? (
                    <button
                        className="action-button action-button-gold"
                        onClick={startScanner}
                    >
                        <Camera size={20} style={{ marginRight: '8px', display: 'inline' }} />
                        Activate Scanner
                    </button>
                ) : (
                    <button
                        className="action-button action-button-red"
                        onClick={stopScanner}
                    >
                        <CameraOff size={20} style={{ marginRight: '8px', display: 'inline' }} />
                        Stop Scanner
                    </button>
                )}
            </div>

            {/* Warning Message */}
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.5 }}
                style={{
                    marginTop: '32px',
                    padding: '16px',
                    background: 'rgba(255, 215, 0, 0.1)',
                    border: '1px solid rgba(255, 215, 0, 0.3)',
                    borderRadius: '12px',
                    display: 'flex',
                    gap: '12px',
                    alignItems: 'flex-start'
                }}
            >
                <AlertCircle size={20} color="var(--warning-gold)" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                    <h4 style={{ fontSize: '14px', marginBottom: '4px', color: 'var(--warning-gold)' }}>
                        Public QR Warning
                    </h4>
                    <p style={{ color: 'var(--text-muted)', fontSize: '12px', lineHeight: '1.5' }}>
                        Malicious QR codes can lead to "quishing" attacks. Always scan before you click.
                    </p>
                </div>
            </motion.div>
        </div>
    );
};

export default QRScanner;
