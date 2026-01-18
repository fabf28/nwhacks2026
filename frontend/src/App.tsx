import React, { useState } from 'react';
import { Home } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import LandingPage from './components/LandingPage';
import WebsiteScanner from './components/WebsiteScanner';
import QRScanner from './components/QRScanner';

type ViewMode = 'landing' | 'website' | 'qr';

const App: React.FC = () => {
  const [activeView, setActiveView] = useState<ViewMode>('landing');
  const [scannedUrl, setScannedUrl] = useState<string | null>(null);

  const handleQRScan = (url: string) => {
    setScannedUrl(url);
    setActiveView('website');
  };

  const goHome = () => {
    setActiveView('landing');
    setScannedUrl(null);
  };

  return (
    <div className="app-container">
      <div className="phone-container">
        {/* Home Icon - Only show when not on landing page */}
        {activeView !== 'landing' && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="home-icon"
            onClick={goHome}
          >
            <Home size={20} color="#fff" />
          </motion.div>
        )}

        {/* Main Content with Page Transitions */}
        <AnimatePresence mode="wait">
          {activeView === 'landing' && (
            <motion.div
              key="landing"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
            >
              <LandingPage
                onCheckQR={() => setActiveView('qr')}
                onCheckWebsite={() => setActiveView('website')}
              />
            </motion.div>
          )}

          {activeView === 'website' && (
            <motion.div
              key="website"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.3 }}
            >
              <WebsiteScanner initialUrl={scannedUrl} />
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
        </AnimatePresence>
      </div>
    </div>
  );
};

export default App;
