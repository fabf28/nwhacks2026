import dns from 'dns';

export interface ReverseDnsResult {
    hostname: string;
    ip: string;
    matches: boolean;
    hostnames: string[];
}

export async function checkReverseDns(hostname: string, ip: string): Promise<ReverseDnsResult> {
    console.log('\n🔄 [REVERSE DNS] Checking PTR record for:', ip);

    try {
        const hostnames = await new Promise<string[]>((resolve, reject) => {
            dns.reverse(ip, (err, hostnames) => {
                if (err) reject(err);
                else resolve(hostnames || []);
            });
        });

        console.log('📥 [REVERSE DNS] PTR records:', hostnames);

        // Check if any of the reverse DNS hostnames match the original hostname
        const matches = hostnames.some(h =>
            h.toLowerCase().includes(hostname.toLowerCase()) ||
            hostname.toLowerCase().includes(h.toLowerCase().split('.')[0])
        );

        console.log(`${matches ? '✅' : '⚠️'} [REVERSE DNS] Match: ${matches}\n`);

        return {
            hostname,
            ip,
            matches,
            hostnames,
        };
    } catch (error: any) {
        console.log('⚠️ [REVERSE DNS] No PTR record found\n');
        return {
            hostname,
            ip,
            matches: false,
            hostnames: [],
        };
    }
}
