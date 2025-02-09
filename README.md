

---

## 🚨 Threat Intelligence Data Extractor 🚨  
Welcome to the **Threat Intelligence Data Extractor** project, developed by **Team Cyber Trace SSPU!** 🎯  
This project was built as a **solution for Problem Statement 1 in Hack IITK 2024 Challenge Round 1**.  
Our tool helps you extract and analyze **critical threat intelligence data** from PDF reports or raw text, including:

- **Indicators of Compromise (IoCs)**
- **Malware Details**
- **Tactics, Techniques, and Procedures (TTPs)**
- **Threat Actors**
- **Targeted Entities**

---

## ✨ Features ✨  
✅ **📄 PDF & Text Input Support:** Analyze threat reports from **uploaded PDF files** or **directly pasted text**.  
✅ **🔍 Advanced Intelligence Extraction:** Extract IoCs, Malware details, TTPs, Threat Actors, and Targeted Entities using **regex, spaCy NLP, and custom wordlists**.  
✅ **🛡️ Text Sanitization:** Prevents injection risks by **removing malicious content** from extracted data.  
✅ **📊 Beautiful Streamlit GUI:** Interactive, futuristic **dark/light mode UI** with **real-time JSON output preview**.  
✅ **📂 JSON Output & Download:** Save and download results as a **structured JSON file** for further analysis.  
✅ **⚡ Fast Processing:** Optimized with regex and NLP to **ensure accuracy & efficiency**.  

---

## ⚙️ Requirements ⚙️  
Before using this tool, ensure that you have the following installed:

### **🔗 Required Dependencies:**  
- **Python 3.12.8**  
- **Required Python libraries:**  
  ```
  streamlit
  pdfplumber
  Pillow
  PyMuPDF
  spacy
  ```
- **spaCy English Model**  
  ```
  python -m spacy download en_core_web_sm
  ```

---

## 🚀 Installation  

### **1️⃣ Clone the repository:**  
```sh
git clone https://github.com/griffin-dox/Threat-Intelligence.git
cd Threat-Intelligence
```

### **2️⃣ Install dependencies:**  
```sh
pip install -r requirements.txt
```

### **3️⃣ Download the spaCy English Model:**  
```sh
python -m spacy download en_core_web_sm
```

---

## 🏃‍♂️ Usage  

### **💻 Run the GUI version (Recommended):**  
```sh
streamlit run gui.py
```
- **Upload a PDF file** or **Paste raw text** for processing.  
- **Select specific intelligence data** (IoCs, Malware, TTPs, etc.) or **extract everything**.  
- **Download the JSON output file** after processing.  

### **📄 Run the CLI version:**  
```sh
python cli.py
```
- Provide the **PDF path or raw text** when prompted.  
- Choose the **data type to extract** (IoCs, TTPs, Malware, etc.).  
- Extracted results will be **displayed in the console** and **saved as JSON** if selected.  

---

## 📥 JSON Output Example  
Once processed, the tool generates a **structured JSON output**, like this:

```json
{
    "IoCs": {
        "IP addresses": ["162.247.241.2", "119.207.79.175"],
        "Domains": ["ctmnews.kr", "nirsoft.net"],
        "Email addresses": [],
        "File hashes": {
            "MD5": ["C7256A0FBAB0F437C3AD4334AA5CDE06"],
            "SHA1": [],
            "SHA256": []
        }
    },
    "TTPs": {
        "Tactics": [["TA0001", "Initial Access"], ["TA0002", "Execution"]],
        "Techniques": []
    },
    "Malware": ["TrickBot", "Cobalt Strike"],
    "Threat Actors": ["Lazarus Group", "APT29"],
    "Targeted Entities": ["Financial Sector", "Healthcare"]
}
```

---

## 🔗 Helpful Resources for Dependencies  
**If you encounter issues while installing dependencies, refer to:**  

- **Python Installation Guide:** [Python Official Website](https://www.python.org/)  
- **Using pip:** [pip Documentation](https://pip.pypa.io/en/stable/)  
- **spaCy Installation Guide:** [spaCy Docs](https://spacy.io/usage)  
- **Library-Specific Docs:**  
  - [pdfplumber](https://github.com/jsvine/pdfplumber)  
  - [Pillow](https://pillow.readthedocs.io/)  
  - [PyMuPDF](https://pymupdf.readthedocs.io/)  

---

## ❗ Limitations ❗  
⚠ **Accuracy:** NLP-based entity recognition **may require manual verification** for complex PDF formats.  
⚠ **PDF Compatibility:** **Encrypted PDFs** or **scanned images** are **not fully supported** (OCR may be needed).  
⚠ **Entity Extraction:** **Some uncommon threat actors or malware names may not be detected** without model training.  

---

## 🚀 Future Improvements 🚀  
✅ **🔍 Enhanced PDF Parsing:** Improve accuracy for **scanned documents and multi-column reports**.  
✅ **🌍 Multi-language Support:** Expand to support **threat reports in multiple languages**.  
✅ **🤖 AI-Based Classification:** Implement **machine learning-based** threat classification.  
✅ **📡 External Threat Intelligence Integration:** Automate data ingestion with **MITRE ATT&CK** and **Threat Intelligence Platforms**.  

---

## 💙 About Us  
**👥 Team Cyber Trace - SSPU**  
We are a passionate **cybersecurity team from SSPU** focused on **AI-driven threat intelligence solutions**.  
We actively **participate in hackathons and coding challenges**, and this project was developed for **Hack IITK 2024 Challenge Round 1**.  

### **🛠 Team Members:**  
🚀 **Ishant Choudhary** - **Team Lead**  
👩‍💻 **Bhagyashree Bharate**  
🛡️ **Bryan Binu**  
💰 **Hrishikesh Hiray**  
📊 **Parth Sujit**  

---
🚀 **"Empowering Cybersecurity through AI & Automation"**  
💻 **Team Cyber Trace | SSPU**  

---
