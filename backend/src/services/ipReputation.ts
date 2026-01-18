export interface IpReputationResult {
    ip: string;
    abuseConfidenceScore: number;
    isWhitelisted: boolean;
    countryCode: string;
    isp: string;
    domain: string;
    totalReports: number;
    lastReportedAt: string | null;
    isSuspicious: boolean;
}

interface AbuseIpDbResponse {
    data: {
        ipAddress: string;
        isPublic: boolean;
        ipVersion: number;
        isWhitelisted: boolean;
        abuseConfidenceScore: number;
        countryCode: string;
        usageType: string;
        isp: string;
        domain: string;
        hostnames: string[];
        totalReports: number;
        numDistinctUsers: number;
        lastReportedAt: string | null;
    };
}

export async function checkIpReputation(ip: string): Promise<IpReputationResult> {
    console.log('\n🛡️ [IP REPUTATION] Checking reputation for:', ip);

    const apiKey = process.env.ABUSEIPDB_API_KEY;

    if (!apiKey) {
        console.warn('⚠️ [IP REPUTATION] API key not configured - skipping check');
        return {
            ip,
            abuseConfidenceScore: 0,
            isWhitelisted: false,
            countryCode: 'Unknown',
            isp: 'Unknown',
            domain: 'Unknown',
            totalReports: 0,
            lastReportedAt: null,
            isSuspicious: false,
        };
    }

    try {
        const response = await fetch(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
            {
                headers: {
                    'Key': apiKey,
                    'Accept': 'application/json',
                },
            }
        );

        console.log('📥 [IP REPUTATION] Response status:', response.status);

        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }

        const data = await response.json() as AbuseIpDbResponse;
        console.log('📦 [IP REPUTATION] Abuse score:', data.data.abuseConfidenceScore);
        console.log('📦 [IP REPUTATION] Total reports:', data.data.totalReports);

        const isSuspicious = data.data.abuseConfidenceScore > 25 || data.data.totalReports > 10;

        console.log(`${isSuspicious ? '🚨' : '✅'} [IP REPUTATION] Suspicious: ${isSuspicious}\n`);

        return {
            ip: data.data.ipAddress,
            abuseConfidenceScore: data.data.abuseConfidenceScore,
            isWhitelisted: data.data.isWhitelisted,
            countryCode: data.data.countryCode,
            isp: data.data.isp,
            domain: data.data.domain,
            totalReports: data.data.totalReports,
            lastReportedAt: data.data.lastReportedAt,
            isSuspicious,
        };
    } catch (error) {
        console.error('❌ [IP REPUTATION] API error:', error);
        return {
            ip,
            abuseConfidenceScore: 0,
            isWhitelisted: false,
            countryCode: 'Unknown',
            isp: 'Unknown',
            domain: 'Unknown',
            totalReports: 0,
            lastReportedAt: null,
            isSuspicious: false,
        };
    }
}
