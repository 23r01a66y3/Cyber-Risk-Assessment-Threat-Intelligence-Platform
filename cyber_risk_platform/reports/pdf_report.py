from fpdf import FPDF
import datetime

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'Cyber Risk Assessment Report', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf(data):
    pdf = PDF()
    pdf.add_page()
    
    # Report Meta
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Date Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(10)
    
    # Table Header
    pdf.set_font("Arial", 'B', 12)
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(30, 10, 'Port', 1, 0, 'C', 1)
    pdf.cell(110, 10, 'Issue', 1, 0, 'C', 1)
    pdf.cell(30, 10, 'Risk Score', 1, 1, 'C', 1)
    
    # Table Body
    pdf.set_font("Arial", '', 12)
    for row in data:
        # row mapping: (id, port, issue, risk_score, timestamp)
        port = str(row[1])
        issue = str(row[2])
        score = str(row[3])
        
        pdf.cell(30, 10, port, 1, 0, 'C')
        pdf.cell(110, 10, issue, 1, 0, 'L')
        pdf.cell(30, 10, score, 1, 1, 'C')

    file_path = "compliance_report.pdf"
    pdf.output(file_path)
    return file_path
