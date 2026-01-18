export interface SafeBrowsingResult {
    isSafe: boolean;
    threats: string[];
    threatTypes: string[];
}

export async function checkSafeBrowsing(url: string): Promise<SafeBrowsingResult> {
    console.log('\n🔍 [SAFE BROWSING] Starting check for:', url);

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        console.warn('⚠️  [SAFE BROWSING] API key not configured - skipping real check');
        return {
            isSafe: true,
            threats: [],
            threatTypes: [],
        };
    }

    console.log('✅ [SAFE BROWSING] API key found, making request to Google...');

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey.substring(0, 10)}...`;
    console.log('📡 [SAFE BROWSING] Endpoint:', apiUrl);

    const requestBody = {
        client: {
            clientId: 'vaultscan',
            clientVersion: '1.0.0',
        },
        threatInfo: {
            threatTypes: [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
        },
    };

    try {
        const fullApiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
        const response = await fetch(fullApiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
        });

        console.log('📥 [SAFE BROWSING] Response status:', response.status);

        const data: any = await response.json();
        console.log('📦 [SAFE BROWSING] Response data:', JSON.stringify(data, null, 2));

        if (data.matches && data.matches.length > 0) {
            const threats: string[] = data.matches.map((match: any) => match.threatType);
            console.log('🚨 [SAFE BROWSING] THREATS DETECTED:', threats);
            return {
                isSafe: false,
                threats: [...new Set(threats)] as string[],
                threatTypes: threats,
            };
        }

        console.log('✅ [SAFE BROWSING] No threats found - URL is safe\n');
        return {
            isSafe: true,
            threats: [],
            threatTypes: [],
        };
    } catch (error) {
        console.error('❌ [SAFE BROWSING] API error:', error);
        return {
            isSafe: true,
            threats: [],
            threatTypes: [],
        };
    }
}
