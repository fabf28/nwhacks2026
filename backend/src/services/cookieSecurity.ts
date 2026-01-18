export interface CookieSecurityResult {
    cookies: {
        name: string;
        secure: boolean;
        httpOnly: boolean;
        sameSite: string | null;
        issues: string[];
    }[];
    totalCookies: number;
    secureCookies: number;
    hasIssues: boolean;
}

function parseCookieAttributes(cookieHeader: string): CookieSecurityResult['cookies'][0] {
    const parts = cookieHeader.split(';').map(p => p.trim());
    const nameValue = parts[0].split('=');
    const name = nameValue[0];

    let secure = false;
    let httpOnly = false;
    let sameSite: string | null = null;
    const issues: string[] = [];

    for (const part of parts.slice(1)) {
        const lowerPart = part.toLowerCase();
        if (lowerPart === 'secure') {
            secure = true;
        } else if (lowerPart === 'httponly') {
            httpOnly = true;
        } else if (lowerPart.startsWith('samesite=')) {
            sameSite = part.split('=')[1];
        }
    }

    // Check for security issues
    if (!secure) {
        issues.push('Missing Secure flag');
    }
    if (!httpOnly) {
        issues.push('Missing HttpOnly flag');
    }
    if (!sameSite || sameSite.toLowerCase() === 'none') {
        issues.push('Weak or missing SameSite attribute');
    }

    return { name, secure, httpOnly, sameSite, issues };
}

export async function checkCookieSecurity(url: string): Promise<CookieSecurityResult> {
    console.log('\n🍪 [COOKIES] Checking cookie security for:', url);

    try {
        const response = await fetch(url, {
            method: 'GET',
            redirect: 'follow',
        });

        const setCookieHeaders = response.headers.getSetCookie?.() || [];

        if (setCookieHeaders.length === 0) {
            console.log('📋 [COOKIES] No cookies set by server\n');
            return {
                cookies: [],
                totalCookies: 0,
                secureCookies: 0,
                hasIssues: false,
            };
        }

        const cookies = setCookieHeaders.map(parseCookieAttributes);
        const secureCookies = cookies.filter(c => c.secure && c.httpOnly && c.sameSite).length;
        const hasIssues = cookies.some(c => c.issues.length > 0);

        for (const cookie of cookies) {
            const icon = cookie.issues.length === 0 ? '✅' : '⚠️';
            console.log(`  ${icon} ${cookie.name}: ${cookie.issues.length === 0 ? 'Secure' : cookie.issues.join(', ')}`);
        }

        console.log(`📊 [COOKIES] ${secureCookies}/${cookies.length} cookies are fully secure\n`);

        return {
            cookies,
            totalCookies: cookies.length,
            secureCookies,
            hasIssues,
        };
    } catch (error: any) {
        console.error('❌ [COOKIES] Error:', error.message);
        return {
            cookies: [],
            totalCookies: 0,
            secureCookies: 0,
            hasIssues: false,
        };
    }
}
