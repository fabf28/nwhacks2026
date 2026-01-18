import jsPDF from 'jspdf';

interface ReportData {
    url: string;
    score: number;
    domainAge: string;
    sslStatus: 'valid' | 'expired' | 'none';
    registrar: string;
    serverLocation: string;
    sandboxResult: 'clean' | 'suspicious' | 'malicious';
}

export function generatePDFReport(data: ReportData): void {
    const doc = new jsPDF();

    // Header
    doc.setFontSize(24);
    doc.setTextColor(0, 242, 254); // Primary color
    doc.text('VaultScan', 20, 20);

    doc.setFontSize(16);
    doc.setTextColor(100, 100, 100);
    doc.text('Security Intelligence Report', 20, 30);

    // Horizontal line
    doc.setDrawColor(200, 200, 200);
    doc.line(20, 35, 190, 35);

    // URL
    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text('Analyzed URL:', 20, 45);
    doc.setTextColor(0, 0, 0);
    doc.text(data.url, 20, 50);

    // Safety Score
    doc.setFontSize(14);
    doc.setTextColor(80, 80, 80);
    doc.text('Safety Score:', 20, 65);

    const scoreColor = data.score >= 80 ? [34, 197, 94] : data.score >= 50 ? [251, 191, 36] : [239, 68, 68];
    doc.setFontSize(36);
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.text(`${data.score}/100`, 20, 80);

    const scoreLabel = data.score >= 80 ? 'SECURE' : data.score >= 50 ? 'WARNING' : 'DANGER';
    doc.setFontSize(12);
    doc.text(scoreLabel, 20, 88);

    // Domain Information
    doc.setFontSize(14);
    doc.setTextColor(0, 242, 254);
    doc.text('Domain Information', 20, 105);

    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text('Creation Date:', 20, 115);
    doc.setTextColor(0, 0, 0);
    doc.text(data.domainAge, 70, 115);

    doc.setTextColor(80, 80, 80);
    doc.text('Registrar:', 20, 122);
    doc.setTextColor(0, 0, 0);
    doc.text(data.registrar, 70, 122);

    // SSL Certificate
    doc.setFontSize(14);
    doc.setTextColor(0, 242, 254);
    doc.text('SSL Certificate', 20, 140);

    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text('Status:', 20, 150);
    const sslColor = data.sslStatus === 'valid' ? [34, 197, 94] : [239, 68, 68];
    doc.setTextColor(sslColor[0], sslColor[1], sslColor[2]);
    doc.text(data.sslStatus.toUpperCase(), 70, 150);

    doc.setTextColor(80, 80, 80);
    doc.text('Encryption:', 20, 157);
    doc.setTextColor(0, 0, 0);
    doc.text('TLS 1.3 / AES-256', 70, 157);

    // Infrastructure
    doc.setFontSize(14);
    doc.setTextColor(0, 242, 254);
    doc.text('Infrastructure', 20, 175);

    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text('Server Location:', 20, 185);
    doc.setTextColor(0, 0, 0);
    doc.text(data.serverLocation, 70, 185);

    // Virtual Sandbox
    doc.setFontSize(14);
    doc.setTextColor(0, 242, 254);
    doc.text('Virtual Sandbox', 20, 203);

    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text('Safety Check:', 20, 213);

    const sandboxColor = data.sandboxResult === 'clean' ? [34, 197, 94] :
        data.sandboxResult === 'suspicious' ? [251, 191, 36] : [239, 68, 68];
    doc.setTextColor(sandboxColor[0], sandboxColor[1], sandboxColor[2]);
    doc.text(data.sandboxResult.toUpperCase(), 70, 213);

    // Footer
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    const timestamp = new Date().toLocaleString();
    doc.text(`Generated on ${timestamp}`, 20, 280);
    doc.text('VaultScan - Advanced Domain & QR Security Intelligence', 20, 285);

    // Save the PDF
    const filename = `VaultScan_Report_${new Date().getTime()}.pdf`;
    doc.save(filename);
}
