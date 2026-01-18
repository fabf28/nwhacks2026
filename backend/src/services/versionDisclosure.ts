export interface VersionDisclosureResult {
    serverVersion: string | null;
    poweredBy: string | null;
    aspNetVersion: string | null;
    phpVersion: string | null;
    allHeaders: { name: string; value: string }[];
    hasDisclosure: boolean;
    riskLevel: 'high' | 'medium' | 'low' | 'none';
}

// Headers that commonly disclose version info
const VERSION_HEADERS = [
    'server',
    'x-powered-by',
    'x-aspnet-version',
    'x-aspnetmvc-version',
    'x-generator',
    'x-drupal-cache',
    'x-varnish',
    'x-nginx-version',
];

function extractVersion(headerValue: string): string | null {
    // Common patterns: "Apache/2.4.41", "nginx/1.18.0", "PHP/7.4.3"
    const versionMatch = headerValue.match(/[\d]+\.[\d]+(?:\.[\d]+)?/);
    return versionMatch ? versionMatch[0] : null;
}

function assessRisk(result: VersionDisclosureResult): 'high' | 'medium' | 'low' | 'none' {
    if (result.phpVersion || result.aspNetVersion) {
        return 'high'; // Language versions are high risk
    }
    if (result.serverVersion && extractVersion(result.serverVersion)) {
        return 'medium'; // Server versions with specific numbers
    }
    if (result.poweredBy) {
        return 'medium';
    }
    if (result.allHeaders.length > 0) {
        return 'low';
    }
    return 'none';
}

export async function checkVersionDisclosure(url: string): Promise<VersionDisclosureResult> {
    console.log('\n📋 [VERSION] Checking for version disclosure...');

    try {
        const response = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
        });

        const allHeaders: { name: string; value: string }[] = [];
        let serverVersion: string | null = null;
        let poweredBy: string | null = null;
        let aspNetVersion: string | null = null;
        let phpVersion: string | null = null;

        // Check all version-related headers
        for (const headerName of VERSION_HEADERS) {
            const value = response.headers.get(headerName);
            if (value) {
                allHeaders.push({ name: headerName, value });
                console.log(`  📌 ${headerName}: ${value}`);

                if (headerName === 'server') {
                    serverVersion = value;
                } else if (headerName === 'x-powered-by') {
                    poweredBy = value;
                    if (value.toLowerCase().includes('php')) {
                        phpVersion = extractVersion(value);
                    }
                } else if (headerName === 'x-aspnet-version') {
                    aspNetVersion = value;
                }
            }
        }

        const result: VersionDisclosureResult = {
            serverVersion,
            poweredBy,
            aspNetVersion,
            phpVersion,
            allHeaders,
            hasDisclosure: allHeaders.length > 0,
            riskLevel: 'none',
        };

        result.riskLevel = assessRisk(result);

        console.log(`📊 [VERSION] Risk level: ${result.riskLevel}\n`);

        return result;
    } catch (error: any) {
        console.error('❌ [VERSION] Error:', error.message);
        return {
            serverVersion: null,
            poweredBy: null,
            aspNetVersion: null,
            phpVersion: null,
            allHeaders: [],
            hasDisclosure: false,
            riskLevel: 'none',
        };
    }
}
