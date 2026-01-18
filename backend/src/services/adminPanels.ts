export interface AdminPanelResult {
    foundPanels: {
        path: string;
        type: 'admin' | 'login' | 'dashboard' | 'api' | 'debug';
    }[];
    hasExposedPanels: boolean;
}

// Common admin/login paths to check
const ADMIN_PATHS = [
    { path: '/admin', type: 'admin' },
    { path: '/administrator', type: 'admin' },
    { path: '/admin/login', type: 'login' },
    { path: '/wp-admin', type: 'admin' },
    { path: '/wp-login.php', type: 'login' },
    { path: '/login', type: 'login' },
    { path: '/signin', type: 'login' },
    { path: '/dashboard', type: 'dashboard' },
    { path: '/panel', type: 'admin' },
    { path: '/cpanel', type: 'admin' },
    { path: '/phpmyadmin', type: 'admin' },
    { path: '/adminer.php', type: 'admin' },
    { path: '/api', type: 'api' },
    { path: '/api/v1', type: 'api' },
    { path: '/graphql', type: 'api' },
    { path: '/debug', type: 'debug' },
    { path: '/console', type: 'debug' },
    { path: '/swagger', type: 'api' },
    { path: '/api-docs', type: 'api' },
] as const;

async function checkPathExists(baseUrl: string, path: string): Promise<boolean> {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);

        const response = await fetch(`${baseUrl}${path}`, {
            method: 'HEAD',
            signal: controller.signal,
            redirect: 'manual',
        });

        clearTimeout(timeout);

        // 200-399 are considered "found" (includes redirects to login)
        return response.status >= 200 && response.status < 400;
    } catch {
        return false;
    }
}

export async function checkAdminPanels(url: string): Promise<AdminPanelResult> {
    console.log('\n🔐 [ADMIN] Checking for exposed admin panels...');

    const parsed = new URL(url);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;

    const foundPanels: AdminPanelResult['foundPanels'] = [];

    // Check paths in parallel batches
    const batchSize = 5;
    for (let i = 0; i < ADMIN_PATHS.length; i += batchSize) {
        const batch = ADMIN_PATHS.slice(i, i + batchSize);
        const results = await Promise.all(
            batch.map(async (panel) => {
                const exists = await checkPathExists(baseUrl, panel.path);
                return { ...panel, exists };
            })
        );

        for (const result of results) {
            if (result.exists) {
                console.log(`  📍 Found: ${result.path} (${result.type})`);
                foundPanels.push({
                    path: result.path,
                    type: result.type,
                });
            }
        }
    }

    console.log(`📊 [ADMIN] Found ${foundPanels.length} exposed endpoints\n`);

    return {
        foundPanels,
        hasExposedPanels: foundPanels.length > 0,
    };
}
