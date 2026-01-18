import net from 'net';

export interface PortScanResult {
    ip: string;
    openPorts: number[];
    suspiciousPorts: number[];
    isSuspicious: boolean;
}

// Common ports to check
const PORTS_TO_SCAN = [
    { port: 21, name: 'FTP', suspicious: true },
    { port: 22, name: 'SSH', suspicious: true },
    { port: 23, name: 'Telnet', suspicious: true },
    { port: 25, name: 'SMTP', suspicious: false },
    { port: 80, name: 'HTTP', suspicious: false },
    { port: 443, name: 'HTTPS', suspicious: false },
    { port: 3306, name: 'MySQL', suspicious: true },
    { port: 3389, name: 'RDP', suspicious: true },
    { port: 5432, name: 'PostgreSQL', suspicious: true },
    { port: 8080, name: 'HTTP-Alt', suspicious: false },
];

async function checkPort(ip: string, port: number, timeout: number = 2000): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = new net.Socket();

        socket.setTimeout(timeout);

        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });

        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });

        socket.connect(port, ip);
    });
}

export async function checkPorts(ip: string): Promise<PortScanResult> {
    console.log('\n🔍 [PORT SCAN] Scanning common ports for:', ip);

    const openPorts: number[] = [];
    const suspiciousPorts: number[] = [];

    // Scan ports in parallel for speed
    const results = await Promise.all(
        PORTS_TO_SCAN.map(async ({ port, name, suspicious }) => {
            const isOpen = await checkPort(ip, port);
            if (isOpen) {
                console.log(`  ✅ Port ${port} (${name}) is OPEN`);
                openPorts.push(port);
                if (suspicious) {
                    suspiciousPorts.push(port);
                }
            }
            return { port, isOpen };
        })
    );

    const isSuspicious = suspiciousPorts.length > 0;

    console.log(`📊 [PORT SCAN] Open ports: ${openPorts.length > 0 ? openPorts.join(', ') : 'standard only'}`);
    console.log(`${isSuspicious ? '🚨' : '✅'} [PORT SCAN] Suspicious: ${isSuspicious}\n`);

    return {
        ip,
        openPorts,
        suspiciousPorts,
        isSuspicious,
    };
}
