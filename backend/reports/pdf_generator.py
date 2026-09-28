import os
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class PDFReportGenerator:
    @staticmethod
    def generate_pdf(scan_data: Dict[str, Any], output_path: str):
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#00f2fe'),
            alignment=1, # Center
            spaceAfter=15
        )

        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1a233a'),
            spaceBefore=10,
            spaceAfter=10
        )

        normal_style = ParagraphStyle(
            'NormalStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#2c3e50')
        )

        elements = []

        # Header Title
        elements.append(Paragraph("<b>Mobile Security & Cryptographic Analyzer</b>", title_style))
        elements.append(Paragraph("Automated APK Security & Vulnerability Assessment Report", ParagraphStyle('Sub', parent=normal_style, alignment=1, textColor=colors.gray)))
        elements.append(Spacer(1, 15))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00f2fe'), spaceAfter=15))

        # Application Summary Table
        app_name = scan_data.get("app_name", "Unknown")
        pkg_name = scan_data.get("package_name", "com.example.app")
        score = scan_data.get("security_score", 100)
        file_name = scan_data.get("file_name", "app.apk")
        file_size = f"{scan_data.get('file_size', 0) / (1024*1024):.2f} MB"
        sha256 = scan_data.get("sha256", "N/A")

        info_data = [
            [Paragraph("<b>Application Name:</b>", normal_style), Paragraph(app_name, normal_style), Paragraph("<b>Security Score:</b>", normal_style), Paragraph(f"<b>{score} / 100</b>", ParagraphStyle('Score', parent=normal_style, textColor=colors.HexColor('#00e676') if score > 70 else colors.HexColor('#ff3d00')))],
            [Paragraph("<b>Package Name:</b>", normal_style), Paragraph(pkg_name, normal_style), Paragraph("<b>File Size:</b>", normal_style), Paragraph(file_size, normal_style)],
            [Paragraph("<b>APK File Name:</b>", normal_style), Paragraph(file_name, normal_style), Paragraph("<b>SHA-256 Hash:</b>", normal_style), Paragraph(f"<font size=7>{sha256}</font>", normal_style)]
        ]

        info_table = Table(info_data, colWidths=[110, 160, 100, 160])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e9ecef')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 15))

        # Severity Summary Table
        counts = scan_data.get("counts", {})
        elements.append(Paragraph("Vulnerability Summary Counter", subtitle_style))
        
        summary_data = [
            ["Critical", "High", "Medium", "Low"],
            [str(counts.get("Critical", 0)), str(counts.get("High", 0)), str(counts.get("Medium", 0)), str(counts.get("Low", 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[130, 130, 130, 140])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor('#d32f2f')),
            ('BACKGROUND', (1,0), (1,0), colors.HexColor('#f57c00')),
            ('BACKGROUND', (2,0), (2,0), colors.HexColor('#fbc02d')),
            ('BACKGROUND', (3,0), (3,0), colors.HexColor('#388e3c')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # Findings Detail Table
        findings: List[Dict[str, Any]] = scan_data.get("findings", [])
        elements.append(Paragraph(f"Detailed Vulnerabilities & Findings ({len(findings)})", subtitle_style))

        if not findings:
            elements.append(Paragraph("No security vulnerabilities detected. Application appears clean.", normal_style))
        else:
            table_data = [["Rule ID", "Severity", "Vulnerability", "Algorithm", "Location"]]
            for f in findings[:30]: # Cap top 30 in PDF
                rule_id = f.get("rule_id", "RULE-000")
                sev = f.get("severity", "Low")
                name = f.get("vulnerability", "Finding")
                algo = f.get("algorithm", "N/A")
                loc = f"{os.path.basename(f.get('file', ''))}:{f.get('line', 0)}"
                
                table_data.append([
                    Paragraph(f"<b>{rule_id}</b>", normal_style),
                    Paragraph(f"<font color='{'red' if sev in ['Critical','High'] else 'orange'}'>{sev}</font>", normal_style),
                    Paragraph(name, normal_style),
                    Paragraph(algo, normal_style),
                    Paragraph(f"<font size=7>{loc}</font>", normal_style)
                ])

            findings_table = Table(table_data, colWidths=[65, 60, 175, 90, 140])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a233a')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(findings_table)

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Security Remediation & Recommendations", subtitle_style))
        remediation_text = (
            "1. <b>Cryptographic Key Management:</b> Migrate all hardcoded encryption keys to the Android Keystore System.<br/>"
            "2. <b>AES Cipher Modes:</b> Replace AES/ECB with AES/GCM authenticated encryption.<br/>"
            "3. <b>Legacy Ciphers:</b> Remove classical ciphers (Caesar, Vigenere), DES, and 3DES.<br/>"
            "4. <b>Hashing Algorithms:</b> Replace MD5 and SHA-1 with SHA-256 or SHA-3.<br/>"
            "5. <b>Network Security:</b> Disallow cleartext HTTP traffic and enforce HTTPS with valid SSL certificates."
        )
        elements.append(Paragraph(remediation_text, normal_style))

        doc.build(elements)
