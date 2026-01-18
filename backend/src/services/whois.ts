export interface WhoisResult {
    createdDate: string;
    ageInDays: number;
    registrar: string;
}

export async function checkWhois(hostname: string): Promise<WhoisResult> {
    // For hackathon: Use a free WHOIS API or mock data
    // Real implementation would use: https://www.whoisxmlapi.com/ or similar

    // Mock implementation - in production, replace with actual API call
    const knownDomains: Record<string, WhoisResult> = {
        'google.com': {
            createdDate: '1997-09-15',
            ageInDays: 10000,
            registrar: 'MarkMonitor Inc.',
        },
        'facebook.com': {
            createdDate: '1997-03-29',
            ageInDays: 10000,
            registrar: 'RegistrarSafe, LLC',
        },
    };

    // Check if it's a known domain
    if (knownDomains[hostname]) {
        return knownDomains[hostname];
    }

    // For unknown domains, simulate a lookup with random age
    // In production: call actual WHOIS API
    const randomAge = Math.floor(Math.random() * 365) + 1;
    const createdDate = new Date();
    createdDate.setDate(createdDate.getDate() - randomAge);

    return {
        createdDate: createdDate.toISOString().split('T')[0],
        ageInDays: randomAge,
        registrar: 'Unknown Registrar',
    };
}
