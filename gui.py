import streamlit as st
from main import process_pdf
import time  # For simulating progress bar

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
st.image("https://via.placeholder.com/150", width=150)  # Replace with your logo URL
st.title("🚀 Cyfer Trace - Threat Intelligence Extractor")  # Fixed typo here

# Sidebar: Extraction Options
with st.sidebar:
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
uploaded_file = st.file_uploader("📂 Upload a PDF file", type=["pdf"], help="Upload a PDF document for analysis.")
user_input = st.text_area("📝 Or paste text here for analysis", "", height=150)
st.markdown('</div>', unsafe_allow_html=True)

# Process Button
if st.button("🔍 Process File/Text"):
    if uploaded_file is None and not user_input:
        st.error("⚠️ Please upload a file or enter text to analyze.")
    else:
        # Progress Bar
        progress_bar = st.progress(0)
        for i in range(100):
            time.sleep(0.02)  # Simulate processing
            progress_bar.progress(i + 1)
        # Simulate loading animation
        with st.spinner("⏳ Processing... Please wait."):
            if uploaded_file:
                temp_path = "temp/temp_uploaded.pdf"
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.read())
                results = process_pdf(temp_path, options)  # Process PDF
            elif user_input:
                results = process_pdf(None, options, user_input)  # Process text input
        # Display results
        if results:
            st.success("✅ Extraction Completed Successfully!")
            st.toast("Results are ready!", icon="🎉")
            
            # Display results in a card
            st.markdown('<div class="card">', unsafe_allow_html=True)
            with st.expander("📊 View Extracted Data", expanded=True):
                st.json(results)  # Display results as formatted JSON
            st.markdown('</div>', unsafe_allow_html=True)
            # Download results as JSON
            st.download_button(
                label="📥 Download Results as JSON",
                data=str(results),
                file_name="extracted_results.json",
                mime="application/json"
            )