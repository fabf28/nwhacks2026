import * as tls from 'tls';

export interface SslResult {
    valid: boolean;
    issuer: string;
    expiresOn: string;
    daysUntilExpiry: number;
}

export async function checkSsl(hostname: string): Promise<SslResult> {
    return new Promise((resolve, reject) => {
        const socket = tls.connect(
            {
                host: hostname,
                port: 443,
                servername: hostname,
                rejectUnauthorized: false, // We want to inspect even invalid certs
            },
            () => {
                const cert = socket.getPeerCertificate();
                socket.end();

                if (!cert || Object.keys(cert).length === 0) {
                    resolve({
                        valid: false,
                        issuer: 'Unknown',
                        expiresOn: 'Unknown',
                        daysUntilExpiry: 0,
                    });
                    return;
                }

                const expiryDate = new Date(cert.valid_to);
                const now = new Date();
                const daysUntilExpiry = Math.floor(
                    (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
                );

                resolve({
                    valid: socket.authorized && daysUntilExpiry > 0,
                    issuer: cert.issuer?.O || 'Unknown',
                    expiresOn: cert.valid_to,
                    daysUntilExpiry,
                });
            }
        );

        socket.on('error', (err) => {
            reject(err);
        });

        // Timeout after 5 seconds
        socket.setTimeout(5000, () => {
            socket.destroy();
            reject(new Error('SSL check timed out'));
        });
    });
}
