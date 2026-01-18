import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Loader2,
  ShieldCheck,
  Shield,
  CheckCircle,
  AlertTriangle,
  XCircle,
  QrCode,
} from 'lucide-react';
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
  const [deepScan, setDeepScan] = useState(false);
  const [hasConsent, setHasConsent] = useState(false);
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
      console.log('Disconnected from backend');
      setIsConnected(false);
      // Reset scanning state if disconnected during a scan
      if (isScanning) {
        setIsScanning(false);
        setProgressUpdates((prev) => [...prev, {
          step: 'error',
          message: 'Connection lost during scan',
          status: 'error'
        }]);
      }
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
          isp: result.checks?.geolocation?.isp || 'Unknown',
          sandboxResult: 'clean',
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
        });
        setIsScanning(false);
        onScanComplete?.();
      }
    });

    socket.on('scan-error', (error) => {
      console.error('Scan error:', error);
      setIsScanning(false);
      setProgressUpdates((prev) => [...prev, {
        step: 'error',
        message: error?.message || 'An error occurred during the scan',
        status: 'error'
      }]);
      setReportData(null); // Clear stale data on error
    });

    return () => {
      socket.disconnect();
    };
  }, [onScanComplete]);

  // Auto-scan when initialUrl is provided AND socket is connected
  useEffect(() => {
    if (
      initialUrl &&
      isConnected &&
      !hasAutoScanned.current &&
      socketRef.current
    ) {
      hasAutoScanned.current = true;
      setUrl(initialUrl);
      setIsFromQR(true);
      setIsScanning(true);
      setReportData(null);
      setProgressUpdates([]);
      socketRef.current.emit('start-scan', { url: initialUrl });
    }
  }, [initialUrl, isConnected]);

  // Normalize URL by adding https:// if no protocol specified
  const normalizeUrl = (inputUrl: string): string => {
    let normalized = inputUrl.trim();
    if (!normalized.match(/^https?:\/\//i)) {
      normalized = 'https://' + normalized;
    }
    return normalized;
  };

  const handleScan = () => {
    if (!url || !socketRef.current) return;

    const normalizedUrl = normalizeUrl(url);
    setUrl(normalizedUrl); // Update the input field with normalized URL

    hasAutoScanned.current = false;
    setIsFromQR(false);
    setIsScanning(true);
    setReportData(null);
    setProgressUpdates([]);

    socketRef.current.emit('start-scan', {
      url: normalizedUrl,
      deepScan: deepScan && hasConsent
    });
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
            borderColor: 'var(--primary)',
          }}
        >
          <QrCode size={20} color="var(--primary)" />
          <span>Scanning URL from QR Code...</span>
        </motion.div>
      )}

      <div
        className="glass-card"
        style={{ padding: '40px', textAlign: 'center' }}
      >
        <h2 style={{ marginBottom: '24px' }}>URL Security Scanner</h2>
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
            style={{
              position: 'absolute',
              right: '16px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
            }}
            size={20}
          />
        </div>

        {/* Deep Scan Toggle */}
        <div style={{
          marginBottom: '20px',
          padding: '16px',
          background: deepScan ? 'rgba(239, 68, 68, 0.1)' : 'rgba(255,255,255,0.03)',
          borderRadius: '12px',
          border: deepScan ? '1px solid var(--danger)' : '1px solid var(--glass-border)',
          transition: 'all 0.3s ease'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: deepScan ? '12px' : '0' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={18} color={deepScan ? 'var(--danger)' : 'var(--text-muted)'} />
              <span style={{ fontWeight: 600 }}>Deep Vulnerability Scan</span>
            </div>
            <label style={{ position: 'relative', display: 'inline-block', width: '48px', height: '24px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={deepScan}
                onChange={(e) => {
                  setDeepScan(e.target.checked);
                  if (!e.target.checked) setHasConsent(false);
                }}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span style={{
                position: 'absolute',
                inset: 0,
                backgroundColor: deepScan ? 'var(--danger)' : 'rgba(255,255,255,0.2)',
                borderRadius: '24px',
                transition: '0.3s',
              }}>
                <span style={{
                  position: 'absolute',
                  left: deepScan ? '26px' : '4px',
                  top: '4px',
                  width: '16px',
                  height: '16px',
                  backgroundColor: 'white',
                  borderRadius: '50%',
                  transition: '0.3s',
                }} />
              </span>
            </label>
          </div>

          {deepScan && (
            <div style={{ textAlign: 'left' }}>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
                Scans for exposed files (.env, .git, backups), admin panels, and version disclosure.
              </p>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={hasConsent}
                  onChange={(e) => setHasConsent(e.target.checked)}
                  style={{ marginTop: '3px', accentColor: 'var(--danger)' }}
                />
                <span style={{ fontSize: '0.85rem', color: 'var(--warning)' }}>
                  I own this website or have explicit permission to perform security testing.
                </span>
              </label>
            </div>
          )}
        </div>
        <button
          className="neon-button"
          onClick={handleScan}
          disabled={isScanning || !url}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px',
          }}
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
            className="glass-card"
            style={{ padding: '24px' }}
          >
            <h3 style={{ marginBottom: '16px' }}>Scan Progress</h3>
            <div
              style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}
            >
              {progressUpdates.map((update, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  style={{ display: 'flex', alignItems: 'center', gap: '12px' }}
                >
                  {getStatusIcon(update.status)}
                  <span
                    style={{
                      color:
                        update.status === 'pending'
                          ? 'var(--text-muted)'
                          : 'var(--text-main)',
                    }}
                  >
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
