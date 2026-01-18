import { GoogleGenerativeAI, Content } from '@google/generative-ai';

const SYSTEM_PROMPT = `You are a cybersecurity expert assistant for VaultScan, a URL security scanner.
You have been provided with security scan results for a website. Your role is to:

1. Explain vulnerabilities found in simple, understandable terms
2. Provide specific, actionable remediation steps
3. Rate the severity of issues and prioritize fixes
4. Answer security questions about the scanned domain
5. Help users understand what the findings mean for their website's security

Be concise but thorough. Use technical terms when appropriate but always explain them.
When suggesting fixes, provide specific code examples or configuration changes when possible.
Always be helpful and encourage good security practices.`;

export interface ChatMessage {
    role: 'user' | 'model';
    content: string;
}

export interface ChatRequest {
    message: string;
    scanContext: any;
    conversationHistory: ChatMessage[];
}

export interface ChatResponse {
    response: string;
    conversationHistory: ChatMessage[];
}

function formatScanContext(scanContext: any): string {
    if (!scanContext) return 'No scan data available.';

    let context = `\n=== SECURITY SCAN RESULTS ===\n`;
    context += `URL: ${scanContext.url}\n`;
    context += `Safety Score: ${scanContext.score}/100\n\n`;

    // Domain info
    if (scanContext.domainAge) {
        context += `DOMAIN:\n`;
        context += `  - Created: ${scanContext.domainAge}\n`;
        context += `  - Registrar: ${scanContext.registrar || 'Unknown'}\n\n`;
    }

    // SSL/TLS
    if (scanContext.ssl) {
        context += `SSL/TLS:\n`;
        context += `  - Status: ${scanContext.sslStatus}\n`;
        context += `  - TLS Version: ${scanContext.ssl.tlsVersion}\n`;
        context += `  - Cipher: ${scanContext.ssl.cipher}\n`;
        context += `  - Cipher Strength: ${scanContext.ssl.cipherStrength}\n\n`;
    }

    // Security Headers
    if (scanContext.securityHeaders) {
        context += `SECURITY HEADERS:\n`;
        context += `  - Grade: ${scanContext.securityHeaders.grade} (${scanContext.securityHeaders.score}/100)\n`;
        if (scanContext.securityHeaders.headers) {
            const missing = scanContext.securityHeaders.headers
                .filter((h: any) => h.status === 'missing')
                .map((h: any) => h.name);
            if (missing.length > 0) {
                context += `  - Missing: ${missing.join(', ')}\n`;
            }
        }
        context += '\n';
    }

    // Cookie Security
    if (scanContext.cookieSecurity) {
        context += `COOKIES:\n`;
        context += `  - Total: ${scanContext.cookieSecurity.totalCookies}\n`;
        context += `  - Secure: ${scanContext.cookieSecurity.secureCookies}\n`;
        context += `  - Has Issues: ${scanContext.cookieSecurity.hasIssues}\n\n`;
    }

    // Vulnerabilities
    if (scanContext.sensitiveFiles?.hasVulnerabilities) {
        context += `⚠️ EXPOSED FILES:\n`;
        for (const file of scanContext.sensitiveFiles.exposedFiles.slice(0, 10)) {
            context += `  - ${file.path} [${file.severity}]: ${file.description}\n`;
        }
        if (scanContext.sensitiveFiles.exposedFiles.length > 10) {
            context += `  ... and ${scanContext.sensitiveFiles.exposedFiles.length - 10} more\n`;
        }
        context += '\n';
    }

    if (scanContext.versionDisclosure?.hasDisclosure) {
        context += `⚠️ VERSION DISCLOSURE:\n`;
        if (scanContext.versionDisclosure.serverVersion) {
            context += `  - Server: ${scanContext.versionDisclosure.serverVersion}\n`;
        }
        if (scanContext.versionDisclosure.poweredBy) {
            context += `  - Powered By: ${scanContext.versionDisclosure.poweredBy}\n`;
        }
        context += '\n';
    }

    if (scanContext.adminPanels?.hasExposedPanels) {
        context += `⚠️ EXPOSED ENDPOINTS:\n`;
        for (const panel of scanContext.adminPanels.foundPanels.slice(0, 10)) {
            context += `  - ${panel.path} (${panel.type})\n`;
        }
        context += '\n';
    }

    // IP Reputation
    if (scanContext.ipReputation) {
        context += `IP REPUTATION:\n`;
        context += `  - Abuse Score: ${scanContext.ipReputation.abuseConfidenceScore}%\n`;
        context += `  - Total Reports: ${scanContext.ipReputation.totalReports}\n\n`;
    }

    // Safe Browsing
    if (scanContext.safeBrowsing) {
        context += `GOOGLE SAFE BROWSING:\n`;
        context += `  - Status: ${scanContext.safeBrowsing.isSafe ? 'CLEAN' : 'THREATS DETECTED'}\n`;
        if (!scanContext.safeBrowsing.isSafe && scanContext.safeBrowsing.threats) {
            context += `  - Threats: ${scanContext.safeBrowsing.threats.join(', ')}\n`;
        }
        context += '\n';
    }

    return context;
}

export async function chat(request: ChatRequest): Promise<ChatResponse> {
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
        console.error('❌ [GEMINI] API key not found');
        return {
            response: 'AI chat is not configured. Please add GEMINI_API_KEY to your environment variables.',
            conversationHistory: request.conversationHistory,
        };
    }

    console.log('\n🤖 [GEMINI] Processing chat request...');

    try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

        // Build conversation history for Gemini
        const scanContextText = formatScanContext(request.scanContext);

        // Create the chat history
        const history: Content[] = [];

        // Add previous messages to history
        for (const msg of request.conversationHistory) {
            history.push({
                role: msg.role,
                parts: [{ text: msg.content }],
            });
        }

        // Start chat with history
        const chat = model.startChat({
            history,
            generationConfig: {
                maxOutputTokens: 1024,
                temperature: 0.7,
            },
        });

        // Build the user message with context if this is the first message
        let userMessage = request.message;
        if (request.conversationHistory.length === 0) {
            userMessage = `${SYSTEM_PROMPT}\n\n${scanContextText}\n\n---\nUser Question: ${request.message}`;
        }

        // Send message and get response
        const result = await chat.sendMessage(userMessage);
        const response = result.response.text();

        console.log('✅ [GEMINI] Response generated');

        // Update conversation history
        const updatedHistory: ChatMessage[] = [
            ...request.conversationHistory,
            { role: 'user', content: request.message },
            { role: 'model', content: response },
        ];

        return {
            response,
            conversationHistory: updatedHistory,
        };
    } catch (error: any) {
        console.error('❌ [GEMINI] Error:', error.message);
        return {
            response: `Sorry, I encountered an error: ${error.message}. Please try again.`,
            conversationHistory: request.conversationHistory,
        };
    }
}
