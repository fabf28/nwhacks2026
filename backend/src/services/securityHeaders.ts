export interface SecurityHeadersResult {
    headers: {
        name: string;
        value: string | null;
        status: 'present' | 'missing' | 'weak';
        description: string;
    }[];
    score: number; // 0-100
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

// Critical security headers to check
const SECURITY_HEADERS = [
    {
        name: 'Strict-Transport-Security',
        description: 'Forces HTTPS connections (HSTS)',
        weight: 20,
        validate: (value: string | null) => {
            if (!value) return 'missing';
            if (value.includes('max-age=') && parseInt(value.match(/max-age=(\d+)/)?.[1] || '0') >= 31536000) {
                return 'present';
            }
            return 'weak';
        }
    },
    {
        name: 'Content-Security-Policy',
        description: 'Prevents XSS and injection attacks (CSP)',
        weight: 25,
        validate: (value: string | null) => value ? 'present' : 'missing'
    },
    {
        name: 'X-Frame-Options',
        description: 'Prevents clickjacking attacks',
        weight: 15,
        validate: (value: string | null) => {
            if (!value) return 'missing';
            if (['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())) return 'present';
            return 'weak';
        }
    },
    {
        name: 'X-Content-Type-Options',
        description: 'Prevents MIME type sniffing',
        weight: 10,
        validate: (value: string | null) => value?.toLowerCase() === 'nosniff' ? 'present' : 'missing'
    },
    {
        name: 'X-XSS-Protection',
        description: 'Legacy XSS protection (deprecated but still useful)',
        weight: 5,
        validate: (value: string | null) => value ? 'present' : 'missing'
    },
    {
        name: 'Referrer-Policy',
        description: 'Controls referrer information leakage',
        weight: 10,
        validate: (value: string | null) => value ? 'present' : 'missing'
    },
    {
        name: 'Permissions-Policy',
        description: 'Controls browser feature access',
        weight: 15,
        validate: (value: string | null) => value ? 'present' : 'missing'
    }
];

function calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
}

export async function checkSecurityHeaders(url: string): Promise<SecurityHeadersResult> {
    console.log('\n🛡️ [HEADERS] Checking security headers for:', url);

    try {
        const response = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
        });

        const results: SecurityHeadersResult['headers'] = [];
        let score = 0;
        let maxScore = 0;

        for (const header of SECURITY_HEADERS) {
            const value = response.headers.get(header.name);
            const status = header.validate(value);

            results.push({
                name: header.name,
                value,
                status,
                description: header.description,
            });

            maxScore += header.weight;
            if (status === 'present') {
                score += header.weight;
            } else if (status === 'weak') {
                score += header.weight * 0.5;
            }

            const icon = status === 'present' ? '✅' : status === 'weak' ? '⚠️' : '❌';
            console.log(`  ${icon} ${header.name}: ${status}`);
        }

        const normalizedScore = Math.round((score / maxScore) * 100);
        const grade = calculateGrade(normalizedScore);

        console.log(`📊 [HEADERS] Score: ${normalizedScore}/100 (Grade: ${grade})\n`);

        return {
            headers: results,
            score: normalizedScore,
            grade,
        };
    } catch (error: any) {
        console.error('❌ [HEADERS] Error:', error.message);
        return {
            headers: SECURITY_HEADERS.map(h => ({
                name: h.name,
                value: null,
                status: 'missing' as const,
                description: h.description,
            })),
            score: 0,
            grade: 'F',
        };
    }
}
