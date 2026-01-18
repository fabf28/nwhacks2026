import jsPDF from 'jspdf';

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
}

export function generatePDFReport(data: ReportData): void {
    const doc = new jsPDF();
    let yPos = 20;

    const addSection = (title: string) => {
        if (yPos > 250) {
            doc.addPage();
            yPos = 20;
        }
        doc.setFontSize(14);
        doc.setTextColor(0, 242, 254);
        doc.text(title, 20, yPos);
        yPos += 10;
    };

    const addRow = (label: string, value: string, color?: number[]) => {
        doc.setFontSize(10);
        doc.setTextColor(80, 80, 80);
        doc.text(label, 20, yPos);
        if (color) {
            doc.setTextColor(color[0], color[1], color[2]);
        } else {
            doc.setTextColor(0, 0, 0);
        }
        doc.text(value, 80, yPos);
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
    yPos += 5;

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
    yPos += 5;

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
    yPos += 5;

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
    yPos += 5;

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
    yPos += 5;

    // 6. Sandbox Result
    addSection('Virtual Sandbox');
    const sandboxColor = data.sandboxResult === 'clean' ? green :
        data.sandboxResult === 'suspicious' ? yellow : red;
    addRow('Safety Check:', data.sandboxResult.toUpperCase(), sandboxColor);

    // Footer
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    const timestamp = new Date().toLocaleString();
    doc.text(`Generated on ${timestamp}`, 20, 280);
    doc.text('VaultScan - Advanced Domain & QR Security Intelligence', 20, 285);

    // Save
    const filename = `VaultScan_Report_${new Date().getTime()}.pdf`;
    doc.save(filename);
}
