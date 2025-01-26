import os
import re
import html
import pdfplumber
from PIL import Image
import fitz  # PyMuPDF
import io

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

if __name__ == "__main__":
    pdf_path = input("Enter the path to the PDF file: ")
    try:
        # Extract text and images from the PDF
        extracted_data = extract_text_and_images(pdf_path)

        # Use the extracted text for further analysis
        text = extracted_data["text"]

        # Sanitize the extracted text to avoid malicious code execution
        sanitized_text = sanitize_text(text)
        print(sanitized_text) # Check sanitized text
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    