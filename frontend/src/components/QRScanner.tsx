import React, { useEffect, useRef, useState } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import { Camera, CameraOff, AlertCircle, RefreshCw } from 'lucide-react';

interface QRScannerProps {
    onScanSuccess: (decodedText: string) => void;
}

const QRScanner: React.FC<QRScannerProps> = ({ onScanSuccess }) => {
    const [scannerStarted, setScannerStarted] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const scannerRef = useRef<Html5Qrcode | null>(null);
    const stoppingRef = useRef(false); // Prevent double-stop

    useEffect(() => {
        return () => {
            // Cleanup: only stop if not already stopping
            const scanner = scannerRef.current;
            if (scanner && !stoppingRef.current) {
                try {
                    if (scanner.isScanning) {
                        stoppingRef.current = true;
                        scanner.stop().catch(() => { });
                    }
                } catch (e) {
                    // Ignore all errors during cleanup
                }
            }
        };
    }, []);

    const startScanner = async () => {
        setError(null);
        stoppingRef.current = false;

        const scanner = new Html5Qrcode("qr-reader-element");
        scannerRef.current = scanner;

        try {
            await scanner.start(
                { facingMode: "environment" },
                { fps: 10, qrbox: { width: 250, height: 250 } },
                (decodedText) => {
                    // Prevent multiple stop calls
                    if (stoppingRef.current) return;
                    stoppingRef.current = true;

                    const finalize = () => {
                        scannerRef.current = null;
                        setScannerStarted(false);
                        alert(`Scanned URL: ${decodedText}`);
                        onScanSuccess(decodedText);
                    };

                    if (scanner.isScanning) {
                        scanner.stop().then(finalize).catch(finalize);
                    } else {
                        finalize();
                    }
                },
                () => { } // ignore parse errors
            );
            setScannerStarted(true);
        } catch (err) {
            console.error(err);
            setError("Failed to access camera. Please ensure permissions are granted.");
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="glass-card" style={{ padding: '40px', textAlign: 'center' }}>
                <h2 style={{ marginBottom: '16px' }}>QR Security Lens</h2>
                <p style={{ color: 'var(--text-muted)', marginBottom: '32px' }}>
                    Instantly intercept and analyze URLs embedded in public QR codes.
                </p>

                <div
                    style={{
                        width: '100%',
                        maxWidth: '400px',
                        margin: '0 auto',
                        borderRadius: '24px',
                        overflow: 'hidden',
                        background: 'rgba(0,0,0,0.5)',
                        minHeight: '300px',
                        border: scannerStarted ? '2px solid var(--primary)' : '2px dashed var(--glass-border)',
                        position: 'relative'
                    }}
                >
                    <div id="qr-reader-element" style={{ width: '100%', height: '100%' }}></div>

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
                                <div style={{ color: 'var(--danger)', textAlign: 'center', padding: '20px' }}>
                                    <AlertCircle size={48} style={{ marginBottom: '16px' }} />
                                    <p>{error}</p>
                                </div>
                            ) : (
                                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                                    <Camera size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                                    <p>Camera standby</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                <div style={{ marginTop: '32px', display: 'flex', gap: '16px', justifyContent: 'center' }}>
                    {!scannerStarted ? (
                        <button className="neon-button" onClick={startScanner} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Camera size={20} />
                            Activate Scanner
                        </button>
                    ) : (
                        <button className="neon-button" onClick={stopScanner} style={{ background: 'var(--danger)', boxShadow: '0 0 15px rgba(255, 77, 77, 0.3)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <CameraOff size={20} />
                            Deactivate
                        </button>
                    )}
                    <button className="neon-button" style={{ background: 'rgba(255,255,255,0.05)', color: 'white', border: '1px solid var(--glass-border)' }}>
                        <RefreshCw size={20} />
                    </button>
                </div>
            </div>

            <div className="glass-card" style={{ padding: '24px', display: 'flex', gap: '20px', alignItems: 'center' }}>
                <div style={{ padding: '12px', borderRadius: '50%', background: 'rgba(255, 204, 0, 0.1)', color: 'var(--warning)' }}>
                    <AlertCircle size={24} />
                </div>
                <div>
                    <h4 style={{ marginBottom: '4px' }}>Public QR Warning</h4>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        Malicious QR codes can lead to "quishing" attacks. Always scan before you click.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default QRScanner;
