import * as tls from 'tls';

export interface SslResult {
    valid: boolean;
    issuer: string;
    expiresOn: string;
    daysUntilExpiry: number;
    // New fields for Section 2
    tlsVersion: string;
    cipher: string;
    cipherStrength: 'strong' | 'moderate' | 'weak';
    certificateChain: {
        subject: string;
        issuer: string;
        validFrom: string;
        validTo: string;
    }[];
    isChainValid: boolean;
}

// Weak ciphers that should be flagged
const WEAK_CIPHERS = [
    'DES', 'RC4', 'RC2', 'MD5', 'NULL', 'EXPORT', 'anon', 'ADH', 'AECDH'
];

// Moderate ciphers (not ideal but acceptable)
const MODERATE_CIPHERS = [
    'SHA1', '3DES', 'CBC'
];

function getCipherStrength(cipher: string): 'strong' | 'moderate' | 'weak' {
    const cipherUpper = cipher.toUpperCase();

    for (const weak of WEAK_CIPHERS) {
        if (cipherUpper.includes(weak)) {
            return 'weak';
        }
    }

    for (const moderate of MODERATE_CIPHERS) {
        if (cipherUpper.includes(moderate)) {
            return 'moderate';
        }
    }

    return 'strong';
}

export async function checkSsl(hostname: string): Promise<SslResult> {
    console.log('\n🔒 [SSL] Starting TLS check for:', hostname);

    return new Promise((resolve, reject) => {
        const socket = tls.connect(
            {
                host: hostname,
                port: 443,
                servername: hostname,
                rejectUnauthorized: false, // We want to inspect even invalid certs
            },
            () => {
                const cert = socket.getPeerCertificate(true); // true = get full chain
                const cipher = socket.getCipher();
                const tlsVersion = socket.getProtocol() || 'Unknown';

                socket.end();

                console.log('📡 [SSL] TLS Version:', tlsVersion);
                console.log('🔐 [SSL] Cipher:', cipher?.name || 'Unknown');

                if (!cert || Object.keys(cert).length === 0) {
                    console.log('❌ [SSL] No certificate found\n');
                    resolve({
                        valid: false,
                        issuer: 'Unknown',
                        expiresOn: 'Unknown',
                        daysUntilExpiry: 0,
                        tlsVersion,
                        cipher: cipher?.name || 'Unknown',
                        cipherStrength: 'weak',
                        certificateChain: [],
                        isChainValid: false,
                    });
                    return;
                }

                const expiryDate = new Date(cert.valid_to);
                const now = new Date();
                const daysUntilExpiry = Math.floor(
                    (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
                );

                // Build certificate chain
                const chain: SslResult['certificateChain'] = [];
                let currentCert: any = cert;
                const seenCerts = new Set<string>();

                while (currentCert && !seenCerts.has(currentCert.fingerprint256)) {
                    seenCerts.add(currentCert.fingerprint256);
                    chain.push({
                        subject: currentCert.subject?.CN || currentCert.subject?.O || 'Unknown',
                        issuer: currentCert.issuer?.CN || currentCert.issuer?.O || 'Unknown',
                        validFrom: currentCert.valid_from,
                        validTo: currentCert.valid_to,
                    });
                    currentCert = currentCert.issuerCertificate;

                    // Prevent infinite loops
                    if (chain.length > 10) break;
                }

                console.log('📜 [SSL] Certificate chain depth:', chain.length);

                const cipherName = cipher?.name || 'Unknown';
                const cipherStrength = getCipherStrength(cipherName);

                console.log(`${cipherStrength === 'strong' ? '✅' : cipherStrength === 'moderate' ? '⚠️' : '❌'} [SSL] Cipher strength: ${cipherStrength}\n`);

                resolve({
                    valid: socket.authorized && daysUntilExpiry > 0,
                    issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                    expiresOn: cert.valid_to,
                    daysUntilExpiry,
                    tlsVersion,
                    cipher: cipherName,
                    cipherStrength,
                    certificateChain: chain,
                    isChainValid: socket.authorized,
                });
            }
        );

        socket.on('error', (err) => {
            console.error('❌ [SSL] Connection error:', err.message);
            reject(err);
        });

        // Timeout after 5 seconds
        socket.setTimeout(5000, () => {
            socket.destroy();
            reject(new Error('SSL check timed out'));
        });
    });
}
