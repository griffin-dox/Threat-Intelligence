import os
import re
import pdfplumber
from PIL import Image
import fitz  # PyMuPDF
import io
import json
import html
from services.extract_entities import (
    extract_threat_actor, 
    extract_malware_names, 
    extract_targeted_entities
)
from services.extract_malware import extract_malware_details
from services.extract_iocs import extract_iocs
from services.extract_ttps import extract_ttp

def extract_text_and_images(pdf_path):
    """Extracts text and images from a PDF file."""
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"File not found: {pdf_path}")
    
    extracted_data = {"text": "", "images": []}
    
    # Extract text from PDF
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            extracted_data["text"] += page.extract_text() + "\n"
    
    # Extract images from PDF
    pdf_document = fitz.open(pdf_path)
    for page_number in range(len(pdf_document)):
        page = pdf_document[page_number]
        images = page.get_images(full=True)
        for img_index, img in enumerate(images):
            xref = img[0]
            base_image = pdf_document.extract_image(xref)
            image_bytes = base_image["image"]
            image_ext = base_image["ext"]
            image = Image.open(io.BytesIO(image_bytes))
            extracted_data["images"].append({
                "page_number": page_number + 1,
                "image_index": img_index + 1,
                "format": image_ext,
                "image": image
            })
    
    return extracted_data

def sanitize_text(text):
    """Sanitizes the extracted text to remove any potential malicious content."""
    sanitized_text = html.escape(text)  # Escape HTML entities

    # Remove HTML tags and JavaScript functions
    sanitized_text = re.sub(r'<.*?>', '', sanitized_text)  # Removes any HTML tags
    sanitized_text = re.sub(r'(?i)(eval|exec|system|alert|console\.log)\(.*?\)', '', sanitized_text)  # Removes JS functions

    # Remove non-ASCII characters and control characters
    sanitized_text = re.sub(r'[^\x00-\x7F]+', '', sanitized_text)
    sanitized_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized_text)

    # Remove SQL/code injection attempts
    sanitized_text = re.sub(r'(--|\#).*', '', sanitized_text)

    return sanitized_text

def process_pdf(pdf_path=None, options=None, user_text=None):
    """
    Process either a PDF file or directly provided text for threat intelligence extraction.
    
    Args:
        pdf_path (str, optional): Path to the PDF file. Default is None.
        options (dict): Extraction options.
        user_text (str, optional): Directly provided text. Default is None.

    Returns:
        dict: Extracted threat intelligence results.
    """
    try:
        if pdf_path:
            extracted_data = extract_text_and_images(pdf_path)
            text = extracted_data["text"]
        elif user_text:
            text = user_text  # Use user input directly
        else:
            return {"Error": "No valid input provided."}

        sanitized_text = sanitize_text(text)
        pdf_filename = os.path.basename(pdf_path) if pdf_path else "User_Text_Input"

        result = {}

        # Extract IoCs
        if options.get('all') or options.get('iocs'):
            iocs = extract_iocs(sanitized_text)
            result['IoCs'] = {
                'IP addresses': iocs['IP addresses'],
                'Domains': iocs['Domains'],
                'Email addresses': iocs['Email addresses'],
                'File hashes': iocs['File hashes']
            }

        # Extract TTPs
        if options.get('all') or options.get('ttps'):
            ttp_data = extract_ttp(sanitized_text)
            result['TTPs'] = ttp_data.get('TTPs', {})

        # Extract Malware Details
        if options.get('all') or options.get('malware'):
            malware_names = extract_malware_names(sanitized_text)
            malware_details = extract_malware_details(sanitized_text)

            result['Malware Name'] = malware_names
            result['Malware Details'] = malware_details

        # Extract Threat Actors
        if options.get('all') or options.get('actors'):
            threat_actors = extract_threat_actor(sanitized_text)
            result['Actors'] = sorted(threat_actors)

        # Extract Targeted Entities
        if options.get('all') or options.get('entities'):
            entities = extract_targeted_entities(sanitized_text)
            result['Entities'] = sorted(entities)
        return result

    except Exception as e:
        print(f"An error occurred: {e}")
        return {"Error": str(e)}

def process_text(text, extracted_filename_entities, options):
    """Processes raw text input and extracts intelligence data."""
    try:
        sanitized_text = sanitize_text(text)

        # Initialize result dictionary
        result = {}

        # Extract IoCs
        if options.get('all') or options.get('iocs'):
            iocs = extract_iocs(sanitized_text)
            result['IoCs'] = {
                'IP addresses': iocs['IP addresses'],
                'Domains': iocs['Domains'],
                'Email addresses': iocs['Email addresses'],
                'File hashes': iocs['File hashes']
            }

        # Extract TTPs
        if options.get('all') or options.get('ttps'):
            ttp_data = extract_ttp(sanitized_text)
            result['TTPs'] = ttp_data.get('TTPs', {})

        # Extract Malware Details
        if options.get('all') or options.get('malware'):
            malware_names = extract_malware_names(sanitized_text)
            malware_details = extract_malware_details(sanitized_text)

            result['Malware'] = malware_names
            result['Malware Details'] = malware_details

        # Extract Threat Actors
        if options.get('all') or options.get('actors'):
            threat_actors = extract_threat_actors(sanitized_text)
            result['Actors'] = sorted(threat_actors)

        # Extract Targeted Entities
        if options.get('all') or options.get('entities'):
            entities = extract_targeted_entities(sanitized_text)
            result['Entities'] = sorted(entities)

        return result
    
    except Exception as e:
        print(f"An error occurred while processing text: {e}")
        return {}
