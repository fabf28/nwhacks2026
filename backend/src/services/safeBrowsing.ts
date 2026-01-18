export interface SafeBrowsingResult {
    isSafe: boolean;
    threats: string[];
    threatTypes: string[];
}

export async function checkSafeBrowsing(url: string): Promise<SafeBrowsingResult> {
    // Google Safe Browsing API v4 endpoint
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        console.warn('Google Safe Browsing API key not configured');
        // Return safe by default if API key is missing (for demo purposes)
        return {
            isSafe: true,
            threats: [],
            threatTypes: [],
        };
    }

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

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
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
        });

        const data = await response.json();

        // If matches are found, the URL is unsafe
        if (data.matches && data.matches.length > 0) {
            const threats = data.matches.map((match: any) => match.threatType);
            return {
                isSafe: false,
                threats: [...new Set(threats)], // Remove duplicates
                threatTypes: threats,
            };
        }

        // No matches = safe
        return {
            isSafe: true,
            threats: [],
            threatTypes: [],
        };
    } catch (error) {
        console.error('Safe Browsing API error:', error);
        // On error, assume safe (fail open for demo)
        return {
            isSafe: true,
            threats: [],
            threatTypes: [],
        };
    }
}
