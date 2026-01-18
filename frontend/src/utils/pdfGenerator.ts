import { jsPDF } from 'jspdf';

interface ReportData {
    url: string;
    score: number;
    domainAge: string;
    sslStatus: 'valid' | 'expired' | 'none' | 'invalid';
    registrar: string;
    serverLocation: string;
    sandboxResult: 'clean' | 'suspicious' | 'malicious';
    isp?: string;
    // SSL/TLS data
    ssl?: {
        tlsVersion: string;
        cipher: string;
        cipherStrength: 'strong' | 'moderate' | 'weak';
        certificateChain?: { subject: string; issuer: string }[];
    };
    // Network data
    reverseDns?: {
        matches: boolean;
        hostnames: string[];
    };
    portScan?: {
        openPorts: number[];
        suspiciousPorts: number[];
        isSuspicious: boolean;
    };
    ipReputation?: {
        abuseConfidenceScore: number;
        totalReports: number;
        isSuspicious: boolean;
    };
    safeBrowsing?: {
        isSafe: boolean;
        threats: string[];
    };
    // HTTP Security
    securityHeaders?: {
        score: number;
        grade: 'A' | 'B' | 'C' | 'D' | 'F';
        headers: { name: string; status: string }[];
    };
    cookieSecurity?: {
        totalCookies: number;
        secureCookies: number;
        hasIssues: boolean;
    };
    // Vulnerability data
    sensitiveFiles?: {
        exposedFiles: { path: string; severity: string; description: string }[];
        hasVulnerabilities: boolean;
        criticalCount: number;
        highCount: number;
    };
    versionDisclosure?: {
        serverVersion: string | null;
        poweredBy: string | null;
        hasDisclosure: boolean;
        riskLevel: string;
    };
    adminPanels?: {
        foundPanels: { path: string; type: string }[];
        hasExposedPanels: boolean;
    };
}

export function generatePDFReport(data: ReportData): void {
    const doc = new jsPDF();
    let yPos = 20;

    const checkPageBreak = (neededSpace: number = 30) => {
        if (yPos > 270 - neededSpace) {
            doc.addPage();
            yPos = 20;
        }
    };

    const addSection = (title: string) => {
        checkPageBreak(40);
        doc.setFontSize(14);
        doc.setTextColor(0, 242, 254);
        doc.text(title, 20, yPos);
        yPos += 10;
    };

    const addRow = (label: string, value: string, color?: number[]) => {
        checkPageBreak();
        doc.setFontSize(10);
        doc.setTextColor(80, 80, 80);
        doc.text(label, 20, yPos);
        if (color) {
            doc.setTextColor(color[0], color[1], color[2]);
        } else {
            doc.setTextColor(0, 0, 0);
        }
        // Truncate long values
        const truncatedValue = value.length > 60 ? value.substring(0, 57) + '...' : value;
        doc.text(truncatedValue, 75, yPos);
        yPos += 7;
    };

    // Colors
    const green = [34, 197, 94];
    const yellow = [251, 191, 36];
    const red = [239, 68, 68];

    // Header
    doc.setFontSize(24);
    doc.setTextColor(0, 242, 254);
    doc.text('VaultScan', 20, yPos);
    yPos += 10;

    doc.setFontSize(16);
    doc.setTextColor(100, 100, 100);
    doc.text('Security Intelligence Report', 20, yPos);
    yPos += 8;

    doc.setDrawColor(200, 200, 200);
    doc.line(20, yPos, 190, yPos);
    yPos += 10;

    // URL
    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text('Analyzed URL:', 20, yPos);
    yPos += 5;
    doc.setTextColor(0, 0, 0);
    doc.text(data.url.substring(0, 80), 20, yPos);
    yPos += 15;

    // Safety Score
    const scoreColor = data.score >= 80 ? green : data.score >= 50 ? yellow : red;
    doc.setFontSize(36);
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.text(`${data.score}/100`, 20, yPos);
    yPos += 8;

    const scoreLabel = data.score >= 80 ? 'SECURE' : data.score >= 50 ? 'WARNING' : 'DANGER';
    doc.setFontSize(12);
    doc.text(scoreLabel, 20, yPos);
    yPos += 15;

    // 1. Domain Information
    addSection('Domain Information');
    addRow('Creation Date:', data.domainAge);
    addRow('Registrar:', data.registrar);
    yPos += 3;

    // 2. SSL Certificate
    addSection('SSL/TLS Certificate');
    const sslColor = data.sslStatus === 'valid' ? green : red;
    addRow('Status:', data.sslStatus.toUpperCase(), sslColor);
    if (data.ssl) {
        addRow('TLS Version:', data.ssl.tlsVersion);
        addRow('Cipher:', data.ssl.cipher);
        const cipherColor = data.ssl.cipherStrength === 'strong' ? green :
            data.ssl.cipherStrength === 'moderate' ? yellow : red;
        addRow('Cipher Strength:', data.ssl.cipherStrength.toUpperCase(), cipherColor);
        if (data.ssl.certificateChain && data.ssl.certificateChain.length > 0) {
            addRow('Chain Depth:', `${data.ssl.certificateChain.length} certificates`);
        }
    }
    yPos += 3;

    // 3. Infrastructure
    addSection('Infrastructure');
    addRow('Server Location:', data.serverLocation);
    addRow('Hosting Provider:', data.isp || 'Unknown');
    if (data.reverseDns) {
        const dnsColor = data.reverseDns.matches ? green : yellow;
        addRow('Reverse DNS:', data.reverseDns.matches ? 'VERIFIED' : 'NO MATCH', dnsColor);
    }
    if (data.portScan) {
        const portColor = data.portScan.isSuspicious ? yellow : green;
        addRow('Port Scan:', data.portScan.isSuspicious ?
            `SUSPICIOUS (${data.portScan.suspiciousPorts.join(', ')})` :
            `CLEAN (${data.portScan.openPorts.length} open)`, portColor);
    }
    yPos += 3;

    // 4. Threat Intelligence
    addSection('Threat Intelligence');
    if (data.safeBrowsing) {
        const sbColor = data.safeBrowsing.isSafe ? green : red;
        addRow('Google Safe Browsing:', data.safeBrowsing.isSafe ? 'CLEAN' :
            `THREAT: ${data.safeBrowsing.threats.join(', ')}`, sbColor);
    }
    if (data.ipReputation) {
        const repColor = data.ipReputation.isSuspicious ? red : green;
        addRow('IP Reputation:', `${data.ipReputation.abuseConfidenceScore}% abuse score`, repColor);
        addRow('Abuse Reports:', `${data.ipReputation.totalReports} reports`);
    }
    yPos += 3;

    // 5. HTTP Security
    addSection('HTTP Security');
    if (data.securityHeaders) {
        const gradeColor = ['A', 'B'].includes(data.securityHeaders.grade) ? green :
            data.securityHeaders.grade === 'C' ? yellow : red;
        addRow('Security Headers:', `Grade ${data.securityHeaders.grade} (${data.securityHeaders.score}/100)`, gradeColor);
    }
    if (data.cookieSecurity) {
        if (data.cookieSecurity.totalCookies === 0) {
            addRow('Cookie Security:', 'No cookies set', green);
        } else {
            const cookieColor = data.cookieSecurity.hasIssues ? yellow : green;
            addRow('Cookie Security:', `${data.cookieSecurity.secureCookies}/${data.cookieSecurity.totalCookies} secure`, cookieColor);
        }
    }
    yPos += 3;

    // 6. Vulnerability Scan Results
    if (data.sensitiveFiles?.hasVulnerabilities || data.versionDisclosure?.hasDisclosure || data.adminPanels?.hasExposedPanels) {
        addSection('⚠️ VULNERABILITIES DETECTED');

        // Sensitive Files
        if (data.sensitiveFiles?.hasVulnerabilities) {
            doc.setFontSize(11);
            doc.setTextColor(red[0], red[1], red[2]);
            doc.text(`Exposed Sensitive Files (${data.sensitiveFiles.criticalCount} critical, ${data.sensitiveFiles.highCount} high)`, 20, yPos);
            yPos += 8;

            doc.setFontSize(9);
            doc.setTextColor(80, 80, 80);
            const filesToShow = data.sensitiveFiles.exposedFiles.slice(0, 8);
            for (const file of filesToShow) {
                checkPageBreak();
                const severityColor = file.severity === 'critical' ? red :
                    file.severity === 'high' ? yellow : [128, 128, 128];
                doc.setTextColor(0, 0, 0);
                doc.text(file.path, 25, yPos);
                doc.setTextColor(severityColor[0], severityColor[1], severityColor[2]);
                doc.text(`[${file.severity.toUpperCase()}]`, 100, yPos);
                yPos += 6;
            }
            if (data.sensitiveFiles.exposedFiles.length > 8) {
                doc.setTextColor(128, 128, 128);
                doc.text(`... and ${data.sensitiveFiles.exposedFiles.length - 8} more`, 25, yPos);
                yPos += 6;
            }
            yPos += 3;
        }

        // Version Disclosure
        if (data.versionDisclosure?.hasDisclosure) {
            checkPageBreak();
            doc.setFontSize(11);
            doc.setTextColor(yellow[0], yellow[1], yellow[2]);
            doc.text('Version Information Leaked', 20, yPos);
            yPos += 8;

            doc.setFontSize(9);
            if (data.versionDisclosure.serverVersion) {
                addRow('Server:', data.versionDisclosure.serverVersion, yellow);
            }
            if (data.versionDisclosure.poweredBy) {
                addRow('Powered By:', data.versionDisclosure.poweredBy, yellow);
            }
            yPos += 3;
        }

        // Admin Panels
        if (data.adminPanels?.hasExposedPanels) {
            checkPageBreak();
            doc.setFontSize(11);
            doc.setTextColor(yellow[0], yellow[1], yellow[2]);
            doc.text(`Exposed Endpoints (${data.adminPanels.foundPanels.length} found)`, 20, yPos);
            yPos += 8;

            doc.setFontSize(9);
            doc.setTextColor(80, 80, 80);
            const panelsToShow = data.adminPanels.foundPanels.slice(0, 10);
            const panelPaths = panelsToShow.map(p => `${p.path} (${p.type})`).join(', ');
            const lines = doc.splitTextToSize(panelPaths, 160);
            for (const line of lines.slice(0, 3)) {
                checkPageBreak();
                doc.text(line, 25, yPos);
                yPos += 6;
            }
            if (data.adminPanels.foundPanels.length > 10) {
                doc.text(`... and ${data.adminPanels.foundPanels.length - 10} more`, 25, yPos);
                yPos += 6;
            }
        }
        yPos += 3;
    }

    // 7. Sandbox Result
    addSection('Virtual Sandbox');
    const sandboxColor = data.sandboxResult === 'clean' ? green :
        data.sandboxResult === 'suspicious' ? yellow : red;
    addRow('Safety Check:', data.sandboxResult.toUpperCase(), sandboxColor);

    // Footer on last page
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    const timestamp = new Date().toLocaleString();
    doc.text(`Generated on ${timestamp}`, 20, 280);
    doc.text('VaultScan - Advanced Domain & QR Security Intelligence', 20, 285);

    // Save
    const filename = `VaultScan_Report_${new Date().getTime()}.pdf`;
    doc.save(filename);
}
