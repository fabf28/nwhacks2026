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
    // First, resolve the hostname to an IP address
    const ip = await new Promise<string>((resolve, reject) => {
        dns.lookup(hostname, (err, address) => {
            if (err) reject(err);
            else resolve(address);
        });
    });

    // Call IP-API (free, no key required for non-commercial use)
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,city,isp,org,query`);
    const data = await response.json() as IpApiResponse;

    if (data.status === 'fail') {
        throw new Error(data.message || 'Geolocation lookup failed');
    }

    return {
        ip: data.query,
        city: data.city || 'Unknown',
        country: data.country || 'Unknown',
        isp: data.isp || 'Unknown',
        org: data.org || 'Unknown',
    };
}
