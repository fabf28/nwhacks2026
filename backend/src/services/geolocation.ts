import dns from 'dns';

interface IpApiResponse {
    status: string;
    message?: string;
    query: string;
    city: string;
    country: string;
    isp: string;
    org: string;
}

export interface GeolocationResult {
    ip: string;
    city: string;
    country: string;
    isp: string;
    org: string;
}

export async function checkGeolocation(hostname: string): Promise<GeolocationResult> {
    console.log('\n🌍 [GEOLOCATION] Starting lookup for:', hostname);

    // First, resolve the hostname to an IP address
    const ip = await new Promise<string>((resolve, reject) => {
        dns.lookup(hostname, (err, address) => {
            if (err) reject(err);
            else resolve(address);
        });
    });

    console.log('🔗 [GEOLOCATION] Resolved IP address:', ip);

    // Call IP-API
    const apiUrl = `http://ip-api.com/json/${ip}?fields=status,message,country,city,isp,org,query`;
    console.log('📡 [GEOLOCATION] Calling IP-API:', apiUrl);

    const response = await fetch(apiUrl);
    const data = await response.json() as IpApiResponse;

    console.log('📥 [GEOLOCATION] Response:', JSON.stringify(data, null, 2));

    if (data.status === 'fail') {
        console.error('❌ [GEOLOCATION] Lookup failed:', data.message);
        throw new Error(data.message || 'Geolocation lookup failed');
    }

    const result = {
        ip: data.query,
        city: data.city || 'Unknown',
        country: data.country || 'Unknown',
        isp: data.isp || 'Unknown',
        org: data.org || 'Unknown',
    };

    console.log('✅ [GEOLOCATION] Result:', `${result.city}, ${result.country} (${result.isp})\n`);

    return result;
}
