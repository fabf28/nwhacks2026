export interface SensitiveFileResult {
    exposedFiles: {
        path: string;
        type: 'config' | 'backup' | 'vcs' | 'secret' | 'info';
        severity: 'critical' | 'high' | 'medium' | 'low';
        description: string;
    }[];
    robotsTxtPaths: string[];
    hasVulnerabilities: boolean;
    criticalCount: number;
    highCount: number;
}

// Files to check for exposure
const SENSITIVE_PATHS = [
    // Environment files (CRITICAL)
    { path: '/.env', type: 'secret', severity: 'critical', description: 'Environment variables exposed - may contain API keys and passwords' },
    { path: '/.env.local', type: 'secret', severity: 'critical', description: 'Local environment file exposed' },
    { path: '/.env.production', type: 'secret', severity: 'critical', description: 'Production environment file exposed' },
    { path: '/.env.backup', type: 'secret', severity: 'critical', description: 'Environment backup exposed' },

    // Version control (HIGH)
    { path: '/.git/config', type: 'vcs', severity: 'high', description: 'Git repository exposed - may leak source code' },
    { path: '/.git/HEAD', type: 'vcs', severity: 'high', description: 'Git HEAD reference exposed' },
    { path: '/.svn/entries', type: 'vcs', severity: 'high', description: 'SVN repository exposed' },
    { path: '/.hg/requires', type: 'vcs', severity: 'high', description: 'Mercurial repository exposed' },

    // Database backups (CRITICAL)
    { path: '/backup.sql', type: 'backup', severity: 'critical', description: 'Database backup exposed' },
    { path: '/dump.sql', type: 'backup', severity: 'critical', description: 'Database dump exposed' },
    { path: '/database.sql', type: 'backup', severity: 'critical', description: 'Database file exposed' },
    { path: '/db.sql', type: 'backup', severity: 'critical', description: 'Database file exposed' },
    { path: '/backup.zip', type: 'backup', severity: 'high', description: 'Backup archive exposed' },

    // Config files (HIGH)
    { path: '/config.php', type: 'config', severity: 'high', description: 'PHP config file exposed' },
    { path: '/wp-config.php', type: 'config', severity: 'critical', description: 'WordPress config exposed - contains database credentials' },
    { path: '/configuration.php', type: 'config', severity: 'high', description: 'Joomla config exposed' },
    { path: '/config.yml', type: 'config', severity: 'high', description: 'YAML config exposed' },
    { path: '/config.json', type: 'config', severity: 'high', description: 'JSON config exposed' },
    { path: '/.htpasswd', type: 'secret', severity: 'critical', description: 'Password file exposed' },
    { path: '/.htaccess', type: 'config', severity: 'medium', description: 'Apache config exposed' },

    // Debug/Info files (MEDIUM)
    { path: '/phpinfo.php', type: 'info', severity: 'medium', description: 'PHP info page exposed - leaks server configuration' },
    { path: '/info.php', type: 'info', severity: 'medium', description: 'PHP info page exposed' },
    { path: '/server-status', type: 'info', severity: 'medium', description: 'Apache server status exposed' },
    { path: '/debug', type: 'info', severity: 'medium', description: 'Debug endpoint exposed' },

    // Logs (HIGH)
    { path: '/error.log', type: 'info', severity: 'high', description: 'Error log exposed - may contain sensitive paths' },
    { path: '/access.log', type: 'info', severity: 'medium', description: 'Access log exposed' },
    { path: '/debug.log', type: 'info', severity: 'high', description: 'Debug log exposed' },
] as const;

async function checkFileExists(baseUrl: string, path: string): Promise<boolean> {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);

        const response = await fetch(`${baseUrl}${path}`, {
            method: 'HEAD',
            signal: controller.signal,
            redirect: 'manual', // Don't follow redirects
        });

        clearTimeout(timeout);

        // Consider 200-299 as "exists", but also check content-type
        // Many servers return 200 with a custom 404 page
        return response.status >= 200 && response.status < 300;
    } catch {
        return false;
    }
}

async function parseRobotsTxt(baseUrl: string): Promise<string[]> {
    try {
        const response = await fetch(`${baseUrl}/robots.txt`);
        if (!response.ok) return [];

        const text = await response.text();
        const disallowedPaths: string[] = [];

        const lines = text.split('\n');
        for (const line of lines) {
            const trimmed = line.trim().toLowerCase();
            if (trimmed.startsWith('disallow:')) {
                const path = line.split(':')[1]?.trim();
                if (path && path !== '/' && path !== '') {
                    disallowedPaths.push(path);
                }
            }
        }

        return disallowedPaths;
    } catch {
        return [];
    }
}

export async function checkSensitiveFiles(url: string): Promise<SensitiveFileResult> {
    console.log('\n🔍 [SENSITIVE FILES] Scanning for exposed files...');

    // Get base URL
    const parsed = new URL(url);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;

    const exposedFiles: SensitiveFileResult['exposedFiles'] = [];

    // Check all sensitive paths in parallel (batched to avoid overwhelming)
    const batchSize = 5;
    for (let i = 0; i < SENSITIVE_PATHS.length; i += batchSize) {
        const batch = SENSITIVE_PATHS.slice(i, i + batchSize);
        const results = await Promise.all(
            batch.map(async (file) => {
                const exists = await checkFileExists(baseUrl, file.path);
                return { ...file, exists };
            })
        );

        for (const result of results) {
            if (result.exists) {
                console.log(`  🚨 FOUND: ${result.path} (${result.severity})`);
                exposedFiles.push({
                    path: result.path,
                    type: result.type,
                    severity: result.severity,
                    description: result.description,
                });
            }
        }
    }

    // Parse robots.txt for interesting paths
    const robotsTxtPaths = await parseRobotsTxt(baseUrl);
    if (robotsTxtPaths.length > 0) {
        console.log(`  📋 Robots.txt disallowed paths: ${robotsTxtPaths.length}`);
    }

    const criticalCount = exposedFiles.filter(f => f.severity === 'critical').length;
    const highCount = exposedFiles.filter(f => f.severity === 'high').length;

    console.log(`📊 [SENSITIVE FILES] Found: ${exposedFiles.length} exposed files (${criticalCount} critical, ${highCount} high)\n`);

    return {
        exposedFiles,
        robotsTxtPaths,
        hasVulnerabilities: exposedFiles.length > 0,
        criticalCount,
        highCount,
    };
}
