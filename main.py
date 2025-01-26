print("Welcome to Threat Intelligence Data Extractor By Team Cyber Trace SSPU. Please wait while we load the required libraries")

import os
import re
import html
import pdfplumber
from PIL import Image
import fitz  # PyMuPDF
import io
import json

from services.extract_entities import extract_threat_actor, extract_targeted_entities
from services.extract_malware import extract_malware_details
from services.extract_iocs import extract_iocs
from services.extract_ttps import extract_ttp

print("Successfully loaded the required libraries")

def extract_text_and_images(pdf_path):
    """
    Extract all text and images from a PDF file.

    Args:
        pdf_path (str): Path to the PDF file.

    Returns:
        dict: A dictionary containing the extracted text and images.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"File not found: {pdf_path}")

    extracted_data = {
        "text": "",
        "images": []
    }

    # Extract text from the PDF using pdfplumber
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            extracted_data["text"] += page.extract_text() + "\n"

    # Extract images from the PDF using PyMuPDF
    pdf_document = fitz.open(pdf_path)
    for page_number in range(len(pdf_document)):
        page = pdf_document[page_number]
        images = page.get_images(full=True)

        for img_index, img in enumerate(images):
            xref = img[0]
            base_image = pdf_document.extract_image(xref)
            image_bytes = base_image["image"]
            image_ext = base_image["ext"]

            # Save the image in memory
            image = Image.open(io.BytesIO(image_bytes))

            # Append the image data to the extracted_data dictionary
            extracted_data["images"].append({
                "page_number": page_number + 1,
                "image_index": img_index + 1,
                "format": image_ext,
                "image": image
            })

    return extracted_data

def sanitize_text(text):
    """
    Sanitizes the extracted text to neutralize any potentially malicious content.
    
    Args:
        text (str): The text to be sanitized.

    Returns:
        str: The sanitized text.
    """
    # Escape any HTML entities (to prevent XSS)
    sanitized_text = html.escape(text)

    # Remove HTML tags and JavaScript functions to avoid injection
    sanitized_text = re.sub(r'<.*?>', '', sanitized_text)  # Removes any HTML tags
    sanitized_text = re.sub(r'(?i)(eval|exec|system|alert|console\.log)\(.*?\)', '', sanitized_text)  # Dangerous function calls

    # Further sanitize to remove special characters and prevent injection attacks
    sanitized_text = re.sub(r'[^\x00-\x7F]+', '', sanitized_text)  # Removes non-ASCII characters
    sanitized_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized_text)  # Removes control characters

    # Remove any SQL injection attempts or code injections (e.g., comments in code)
    sanitized_text = re.sub(r'(--|\#).*', '', sanitized_text)  # Removes SQL-style comments

    return sanitized_text

def process_pdf(pdf_path):
    """
    Process the PDF file to extract threat intelligence data.

    Args:
        pdf_path (str): Path to the PDF file.

    Returns:
        dict: Extracted threat intelligence data.
    """
    try:
        # Extract text and images from the PDF
        extracted_data = extract_text_and_images(pdf_path)

        # Use the extracted text for further analysis
        text = extracted_data["text"]

        # Sanitize the extracted text
        sanitized_text = sanitize_text(text)

        # Extract IoCs, TTPs, and Malware details using the other functions
        iocs = extract_iocs(sanitized_text)
        actors = extract_threat_actor(sanitized_text)
        entities = extract_targeted_entities(sanitized_text)
        malware_data = extract_malware_details(sanitized_text)
        ttp_data = extract_ttp(sanitized_text)

        # Prepare the result
        result = {
            'IoCs': {
                'IP addresses': iocs['IP addresses'],
                'Domains': iocs['Domains'],
                'Email addresses': iocs['Email addresses'],
                'File hashes': iocs['File hashes']
            },
            'TTPs': ttp_data.get('TTPs', {}),
            'Malware': malware_data,
            'Actors': actors,
            'Entities': entities
        }

        return result

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def download_data(data, filename="threat_intelligence_data.json"):
    """
    Save the extracted threat intelligence data to a JSON file.

    Args:
        data (dict): The threat intelligence data to be saved.
        filename (str): The filename to save the data as.
    """
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Data successfully saved as {filename}")

if __name__ == "__main__":
    # Take user input for the file path
    pdf_path = input("Enter the path to the PDF file: ")

    print("\nRecieved the PDF \nProcessing the PDF file... Please Hold Tight...:)")
    try:
        # Process the PDF to extract threat intelligence data
        threat_intelligence_data = process_pdf(pdf_path)

        # Display the extracted threat intelligence data
        if threat_intelligence_data:
            print("\nExtracted Threat Intelligence Data:")
            print(f"IOCs: {threat_intelligence_data['IoCs']}")
            print(f"TTPs: {threat_intelligence_data['TTPs']}")
            print(f"Malware: {threat_intelligence_data['Malware']}")
            print(f"Actors: {threat_intelligence_data['Actors']}")
            print(f"Entities: {threat_intelligence_data['Entities']}")

            # Ask user if they want to download the data
            download_choice = input("\nDo you want to download the extracted data? (Y/N): ").strip().lower()

            if download_choice == 'y':
                download_data(threat_intelligence_data)
            else:
                print("Data not downloaded.")
        else:
            print("No threat intelligence data extracted.")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
