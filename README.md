# 🚨 Threat Intelligence Data Extractor 🚨

Welcome to the **Threat Intelligence Data Extractor** project, developed by **Team Cyber Trace SSPU**! This Project was made as Solution for Problem Statement 1 in Hack IITK 2024 Hackathon Challenge round 1. 
This tool helps you extract and analyze critical threat intelligence data from PDF reports, including:

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

- **Python 3.12.8**  
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
   git clone https://github.com/griffin-dox/Threat-Intelligence.git
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

## 🔗 Helpful Resources for Dependencies 🔗

If you encounter any issues while installing the required dependencies, refer to the following resources:

### Installing Python (3.12.8 Recommended)
- [Python Official Website](https://www.python.org/downloads/)
- [Guide to Installing Python on Windows/Mac/Linux](https://realpython.com/installing-python/)

### Using pip to Install Packages
- [pip Documentation](https://pip.pypa.io/en/stable/)
- [Beginner's Guide to pip](https://realpython.com/what-is-pip/)

### Installing spaCy
- Spacy is only Compatible on Python 3.12.8 and Below please Python <= 3.12.8
- [spaCy Installation Guide](https://spacy.io/usage)
- [Downloading spaCy Models](https://spacy.io/usage/models)

### Library-Specific Guides
- **pdfplumber**: [GitHub Documentation](https://github.com/jsvine/pdfplumber)
- **Pillow**: [Official Installation Guide](https://pillow.readthedocs.io/en/stable/installation.html)
- **PyMuPDF**: [PyMuPDF Documentation](https://pymupdf.readthedocs.io/en/latest/)

If you still face issues, feel free to ask your team or the community for assistance.

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
