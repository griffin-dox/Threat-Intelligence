import streamlit as st
from main import process_pdf

# Streamlit UI
st.title("🚀 Cyber Trace - Threat Intelligence Extractor")

# File Upload and Text Input
uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])
user_input = st.text_area("Or paste text here for analysis", "")

# Checkbox for selecting extraction options
st.sidebar.header("Select Extraction Options")
extract_all = st.sidebar.checkbox("Extract All", value=True)
extract_iocs = st.sidebar.checkbox("Extract IoCs", value=False)
extract_malware = st.sidebar.checkbox("Extract Malware", value=False)
extract_ttps = st.sidebar.checkbox("Extract TTPs", value=False)
extract_actors = st.sidebar.checkbox("Extract Threat Actors", value=False)
extract_entities = st.sidebar.checkbox("Extract Targeted Entities", value=False)

# Create options dictionary
options = {
    "all": extract_all,
    "iocs": extract_iocs,
    "malware": extract_malware,
    "ttps": extract_ttps,
    "actors": extract_actors,
    "entities": extract_entities
}

# Process button
if st.button("Process File/Text"):
    if uploaded_file is not None:
        # Save uploaded file temporarily
        temp_path = "temp_uploaded.pdf"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())

        results = process_pdf(temp_path, options)  # Process PDF
    elif user_input:
        results = process_pdf(None, options, user_input)  # Process text input
    else:
        st.error("Please upload a file or enter text to analyze.")

    if results:
        st.subheader("Extracted Threat Intelligence Data")
        st.json(results)  # Display results as formatted JSON

        # Save results as JSON
        st.download_button(
            label="Download Results as JSON",
            data=str(results),
            file_name="extracted_results.json",
            mime="application/json"
        )
