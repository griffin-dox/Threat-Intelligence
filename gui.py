import streamlit as st
from main import process_pdf
import time  # For simulating progress bar
import os

# Custom CSS for advanced styling
st.markdown("""
    <style>
        /* Galaxy Gradient Background */
        html, body {
            height: 100%; /* Ensure full height */
            margin: 0; /* Remove default margin */
            padding: 0; /* Remove default padding */
            overflow-x: hidden; /* Prevent horizontal scrolling */
        }
        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, #000000, #1a1a2e, #16213e, #0f3443, #1a1a2e, #000000);
            background-size: 400% 400%; /* Smooth transition effect */
            animation: gradient-animation 15s ease infinite; /* Animates the gradient */
            color: #ffffff; /* White text for contrast */
        }
        @keyframes gradient-animation {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        /* Add a minimal symmetric diagonal pattern */
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                45deg,
                rgba(255, 255, 255, 0.05), /* Light diagonal lines */
                rgba(255, 255, 255, 0.05) 10px,
                transparent 10px,
                transparent 20px
            );
            z-index: -1; /* Place it behind other content */
            pointer-events: none; /* Ensure it doesn't block interactions */
        }
        /* Make the Streamlit app container fully transparent */
        .stApp {
            background-color: transparent !important; /* Fully transparent */
            backdrop-filter: none !important; /* Disable blur effects */
            border: none !important; /* Remove borders */
            box-shadow: none !important; /* Remove shadows */
            padding: 0 !important; /* Remove padding */
            margin: 0 !important; /* Remove margin */
        }
        /* Title Styling */
        h1 {
            color: #00bcd4; /* Cyan for a futuristic look */
            text-align: center;
            font-size: 2.5rem;
            margin-bottom: 0 !important; /* Remove bottom margin */
            padding-bottom: 0 !important; /* Remove bottom padding */
        }
        /* Sidebar Styling */
        .sidebar .sidebar-content {
            background-color: #1a1a2e; /* Dark blue for sidebar */
            border-radius: 10px;
            padding: 1rem;
        }
        .sidebar .stCheckbox > label {
            font-weight: bold;
            color: #00bcd4; /* Cyan text for contrast */
        }
        /* Buttons Styling */
        .stButton > button {
            background-color: #00bcd4; /* Cyan buttons */
            color: white;
            border: none;
            border-radius: 8px;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            transition: transform 0.2s ease-in-out;
        }
        .stButton > button:hover {
            background-color: #00acc1; /* Slightly darker cyan on hover */
            transform: scale(1.05);
        }
        /* JSON Output Styling */
        pre {
            background-color: #1a1a2e; /* Dark blue background for JSON */
            border: 1px solid #00bcd4; /* Cyan border */
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
        }
        /* Card Styling */
        .card {
            background-color: #1a1a2e; /* Dark blue card */
            border: 1px solid #00bcd4; /* Cyan border */
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        /* Responsive Design Adjustments */
        @media (max-width: 768px) {
            h1 {
                font-size: 2rem; /* Smaller title for mobile */
            }
            .stApp {
                padding: 0.5rem; /* Reduced padding for mobile */
            }
            .sidebar .sidebar-content {
                padding: 0.5rem; /* Reduced padding for mobile */
            }
        }
    </style>
""", unsafe_allow_html=True)

# Add a logo (optional)
st.title("Cyfer Trace - Threat Intelligence Extractor")

# Sidebar: Extraction Options
with st.sidebar:
    st.image("static/logo.webp", width=150)
    st.markdown("<h2 style='color: #00bcd4;'>⚙️ Extraction Options</h2>", unsafe_allow_html=True)
    extract_all = st.checkbox("Extract All", value=True, help="Extract all available threat intelligence data.")
    extract_iocs = st.checkbox("Extract IoCs", value=False, help="Extract Indicators of Compromise (IoCs).")
    extract_malware = st.checkbox("Extract Malware", value=False, help="Extract malware-related information.")
    extract_ttps = st.checkbox("Extract TTPs", value=False, help="Extract Tactics, Techniques, and Procedures (TTPs).")
    extract_actors = st.checkbox("Extract Threat Actors", value=False, help="Extract information about threat actors.")
    extract_entities = st.checkbox("Extract Targeted Entities", value=False, help="Extract targeted entities.")

# Create options dictionary
options = {
    "all": extract_all,
    "iocs": extract_iocs,
    "malware": extract_malware,
    "ttps": extract_ttps,
    "actors": extract_actors,
    "entities": extract_entities
}

# Main Content: File Upload and Text Input
st.markdown('<div class="card">', unsafe_allow_html=True)
uploaded_files = st.file_uploader("📂 Upload PDF files", type=["pdf"], accept_multiple_files=True, help="Upload multiple PDF documents for analysis.")
user_input = st.text_area("📝 Or paste text here for analysis", "", height=150)
st.markdown('</div>', unsafe_allow_html=True)

# Process Button
if st.button("🔍 Process Files/Text"):
    if not uploaded_files and not user_input:
        st.error("⚠️ Please upload files or enter text to analyze.")
    else:
        results_dict = {}  # Dictionary to store results for each file
        progress_bar = st.progress(0)

        # Process uploaded files
        if uploaded_files:
            total_files = len(uploaded_files)
            for i, uploaded_file in enumerate(uploaded_files):
                with st.spinner(f"⏳ Processing file {i + 1}/{total_files}: {uploaded_file.name}..."):
                    temp_path = f"temp/{uploaded_file.name}"
                    os.makedirs("temp", exist_ok=True)  # Ensure temp directory exists
                    with open(temp_path, "wb") as f:
                        f.write(uploaded_file.read())
                    results = process_pdf(temp_path, options)  # Process PDF
                    results_dict[uploaded_file.name] = results  # Store results
                    time.sleep(0.02)  # Simulate processing
                    progress_bar.progress((i + 1) / total_files)

        # Process user input text
        if user_input:
            with st.spinner("⏳ Processing text input..."):
                results = process_pdf(None, options, user_input)  # Process text input
                results_dict["User Input"] = results  # Store results
                time.sleep(0.02)  # Simulate processing
                progress_bar.progress(1.0)

        # Display results
        if results_dict:
            st.success("✅ Extraction Completed Successfully!")
            st.toast("Results are ready!", icon="🎉")

            # Display results for each file/input in separate sections
            for file_name, results in results_dict.items():
                st.markdown(f'<div class="card"><h3>📄 {file_name}</h3></div>', unsafe_allow_html=True)
                with st.expander(f"📊 View Extracted Data for {file_name}", expanded=False):
                    st.json(results)  # Display results as formatted JSON

            # Download all results as a single JSON file
            st.download_button(
                label="📥 Download All Results as JSON",
                data=str(results_dict),
                file_name="extracted_results.json",
                mime="application/json"
            )