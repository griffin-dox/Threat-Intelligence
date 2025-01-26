# 🚨 Threat Intelligence Data Extractor 🚨(Private till 27th Jan 12:00 AM)

Welcome to the **Threat Intelligence Data Extractor** project, developed by **Team Cyber Trace @ Symbiosis Skills and Professional University, Kiwale, Pune, (SSPU)**! This tool helps you extract and analyze critical threat intelligence data from PDF reports, including:

- **Indicators of Compromise (IoCs)**
- **Malware Details**
- **Tactics, Techniques, and Procedures (TTPs)**
- **Threat Actors**
- **Targeted Entities**

---

## ✨ Features ✨

- **PDF Extraction**: Seamlessly extract both text and images from PDF reports.
- **Advanced Intelligence Extraction**: Identify and extract key IoCs, Malware details, TTPs, Threat Actors, and Targeted Entities.
- **Text Sanitization**: Safeguard your data by removing potentially harmful content.
- **JSON Output**: Export your results in a structured, downloadable JSON format.

---

## ⚙️ Requirements ⚙️

Before using this tool, ensure that you have the following installed:

- **Python 3.8+**  
- Required Python libraries:
  - `pdfplumber`
  - `Pillow`
  - `PyMuPDF`
  - `spaCy`

Additionally, you'll need the **spaCy English model** to process the text effectively.

---

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/itzCodeItIshant/Threat-Intelligence.git
   cd Threat-Intelligence
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Download the spaCy English model**:
   ```bash
   python -m spacy download en_core_web_sm
   ```

---

## 🏃‍♂️ Usage

1. Run the script:
   ```bash
   python main.py
   ```

2. Provide the PDF path when prompted.

3. Review and download:
   - The tool will display the extracted threat intelligence data in your console.
   - Choose to download the data as a structured JSON file.

---

## 💾 Data Download

Once processing is complete, the tool will give you the option to download the extracted data as a JSON file for further analysis.

---

## ❗ Limitations ❗

- **Accuracy**: Extraction accuracy may vary depending on the PDF layout and formatting. Complex reports may require additional manual verification.
- **PDF Compatibility**: Only supports standard text and image-based PDFs. Some specialized or encrypted PDFs may not be fully supported.
- **Entity Extraction**: The accuracy of entity recognition is dependent on the quality and clarity of the text. Some uncommon entities might be missed.

---

## 🚀 Future Improvements 🚀

- **Enhanced PDF Parsing**: Improve extraction accuracy for complex PDF layouts, including scanned documents.
- **Broader Intelligence Extraction**: Expand the tool's ability to identify more diverse IoCs, TTPs, and other threat intelligence data.
- **Integration with Threat Intelligence Platforms**: Enable direct integration with external threat intelligence platforms for automated data ingestion.
- **Multi-language Support**: Add support for multiple languages to enhance global applicability.
- **AI-Based Classification**: Implement machine learning algorithms for more advanced threat actor and malware categorization.
