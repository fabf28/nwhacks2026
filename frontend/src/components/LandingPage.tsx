import React from 'react';
import { motion } from 'framer-motion';

interface LandingPageProps {
    onCheckQR: () => void;
    onCheckWebsite: () => void;
}

const LandingPage: React.FC<LandingPageProps> = ({ onCheckQR, onCheckWebsite }) => {
    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            minHeight: '800px',
            padding: '40px 20px'
        }}>
            {/* Logo and Mission Statement */}
            <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6 }}
                style={{ textAlign: 'center', marginBottom: '60px' }}
            >
                <h1 className="neon-text-pink" style={{
                    fontSize: '42px',
                    marginBottom: '24px',
                    textTransform: 'uppercase'
                }}>
                    SAFESITE
                </h1>
                <p style={{
                    color: 'var(--text-muted)',
                    fontSize: '14px',
                    lineHeight: '1.6',
                    maxWidth: '280px',
                    margin: '0 auto'
                }}>
                    Welcome to SafeSite! Our mission is to provide a safe way to check the vulnerabilities or threat potential of a website.
                </p>
            </motion.div>

            {/* Action Prompt */}
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3, duration: 0.6 }}
            >
                <p style={{
                    textAlign: 'center',
                    color: 'var(--text-muted)',
                    fontSize: '14px',
                    marginBottom: '32px'
                }}>
                    What would you like to do?
                </p>

                {/* Action Buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className="action-button action-button-red"
                        onClick={onCheckQR}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.5, duration: 0.4 }}
                    >
                        Check a QR Code
                    </motion.button>

                    <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className="action-button action-button-gold"
                        onClick={onCheckWebsite}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.6, duration: 0.4 }}
                    >
                        Check a Website
                    </motion.button>
                </div>
            </motion.div>
        </div>
    );
};

export default LandingPage;
