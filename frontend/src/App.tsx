import React, { useState } from 'react';
import { Shield, Link, Camera, History, Settings } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import LinkScanner from './components/LinkScanner';
import QRScanner from './components/QRScanner';

type ViewMode = 'link' | 'qr' | 'history' | 'settings';

const App: React.FC = () => {
  const [activeView, setActiveView] = useState<ViewMode>('link');
  const [scannedUrl, setScannedUrl] = useState<string | null>(null);

  const handleQRScan = (url: string) => {
    // Store the scanned URL and switch to link scanner
    setScannedUrl(url);
    setActiveView('link');
  };

  const clearScannedUrl = () => {
    setScannedUrl(null);
  };

  const navItems = [
    { id: 'link', icon: Link, label: 'Link Scanner' },
    { id: 'qr', icon: Camera, label: 'QR Scanner' },
    { id: 'history', icon: History, label: 'Reports' },
    { id: 'settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <div className="app-container">
      {/* Sidebar / Navigation */}
      <nav className="glass-card" style={{
        position: 'fixed',
        left: '20px',
        top: '20px',
        bottom: '20px',
        width: '80px',
        zIndex: 100,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '24px 0',
        gap: '32px'
      }}>
        <div style={{ color: 'var(--primary)', marginBottom: '20px' }}>
          <Shield size={32} />
        </div>

        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveView(item.id as ViewMode)}
            style={{
              background: 'none',
              border: 'none',
              color: activeView === item.id ? 'var(--primary)' : 'var(--text-muted)',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '4px'
            }}
          >
            <item.icon size={24} style={{
              filter: activeView === item.id ? 'drop-shadow(0 0 8px var(--primary-glow))' : 'none'
            }} />
            <span style={{ fontSize: '10px', fontWeight: 600 }}>{item.label.split(' ')[0]}</span>
          </button>
        ))}
      </nav>

      {/* Main Content Area */}
      <main style={{
        marginLeft: '120px',
        padding: '40px',
        minHeight: '100vh',
        display: 'flex',
        justifyContent: 'center'
      }}>
        <div style={{ width: '100%', maxWidth: '900px' }}>
          <header style={{ marginBottom: '40px' }}>
            <motion.h1
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              style={{ fontSize: '2.5rem', fontWeight: 800, marginBottom: '8px' }}
            >
              Vault<span style={{ color: 'var(--primary)' }}>Scan</span>
            </motion.h1>
            <p style={{ color: 'var(--text-muted)' }}>Advanced domain & QR security intelligence</p>
          </header>

          <AnimatePresence mode="wait">
            {activeView === 'link' && (
              <motion.div
                key="link"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.3 }}
              >
                <LinkScanner
                  initialUrl={scannedUrl}
                  onScanComplete={clearScannedUrl}
                />
              </motion.div>
            )}

            {activeView === 'qr' && (
              <motion.div
                key="qr"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.3 }}
              >
                <QRScanner onScanSuccess={handleQRScan} />
              </motion.div>
            )}

            {(activeView === 'history' || activeView === 'settings') && (
              <motion.div
                key="placeholder"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                style={{ textAlign: 'center', marginTop: '100px' }}
              >
                <p style={{ color: 'var(--text-muted)', fontSize: '1.2rem' }}>
                  This feature is coming soon in the next update.
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Decorative background elements */}
      <div style={{
        position: 'fixed',
        top: '10%',
        right: '5%',
        width: '300px',
        height: '300px',
        background: 'var(--primary)',
        filter: 'blur(150px)',
        opacity: 0.05,
        pointerEvents: 'none'
      }} />
      <div style={{
        position: 'fixed',
        bottom: '10%',
        left: '10%',
        width: '400px',
        height: '400px',
        background: 'var(--secondary)',
        filter: 'blur(200px)',
        opacity: 0.05,
        pointerEvents: 'none'
      }} />
    </div>
  );
};

export default App;
