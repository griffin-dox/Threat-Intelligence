import os
import json
from main import process_pdf

# ASCII Art for Team Logo
def display_logo():
    logo = """

 ██████╗ ██╗   ██╗  ███████╗  ███████╗  ██████╗      ████████╗  ██████╗    █████╗    ██████╗  ███████╗               
██╔════╝ ╚██╗ ██╔╝  ██╔════╝  ██╔════╝  ██╔══██╗     ╚══██╔══╝  ██╔══██╗  ██╔══██╗  ██╔════╝  ██╔════╝   
██║       ╚████╔╝   █████╗    █████╗    ██████╔╝        ██║     ██████╔╝  ███████║  ██║       █████╗                      
██║        ╚██╔╝    ██╔══╝    ██╔══╝    ██╔══██╗        ██║     ██╔══██╗  ██╔══██║  ██║       ██╔══╝     
╚██████╗    ██║     ██║       ███████╗  ██║  ██║        ██║     ██║  ██║  ██║  ██║  ╚██████╗  ███████╗  
 ╚═════╝    ╚═╝     ╚═╝       ╚══════╝  ╚═╝  ╚═╝        ╚═╝     ╚═╝  ╚═╝  ╚═╝  ╚═╝   ╚═════╝  ╚══════╝                                                                               


"""
    print(logo)

# Command Menu
def display_menu():
    print("Welcome to Cyber Trace - Threat Intelligence Extractor")
    print("========================================================")
    print("Usage:")
    print("  -a : Extract all intelligence data")
    print("  -i : Extract Indicators of Compromise (IoCs)")
    print("  -m : Extract Malware details")
    print("  -t : Extract Tactics, Techniques, and Procedures (TTPs)")
    print("========================================================")

# Save Results to JSON File
def save_to_json(data):
    filename = input("Enter the filename to save the results (e.g., output.json): ").strip()
    if not filename.endswith(".json"):
        filename += ".json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Results successfully saved as {filename}")

# Main CLI Function
def cli_frontend():
    # Display the team logo and menu
    display_logo()
    display_menu()

    # Take PDF file input
    pdf_path = input("Enter the path to the PDF file: ").strip()
    if not os.path.exists(pdf_path):
        print("Error: File not found. Please check the path and try again.")
        return

    # Ask user for extraction options
    print("\nSelect the type of intelligence to extract:")
    print("  [A] All")
    print("  [I] Indicators of Compromise (IoCs)")
    print("  [M] Malware Details")
    print("  [T] Tactics, Techniques, and Procedures (TTPs)")
    choice = input("Enter your choice (e.g., 'A', 'I,M,T'): ").strip().lower()

    # Parse user choices
    options = {
        'all': False,
        'iocs': False,
        'malware': False,
        'ttps': False,
        'actors': False,
        'entities': False
    }

    if 'a' in choice:
        options['all'] = True
    else:
        if 'i' in choice:
            options['iocs'] = True
        if 'm' in choice:
            options['malware'] = True
        if 't' in choice:
            options['ttps'] = True
        options['actors'] = options['all'] or options['malware']
        options['entities'] = options['all'] or options['malware']

    # Process the PDF and extract data
    print("\nProcessing the PDF file... Please wait...")
    result = process_pdf(pdf_path, options)

    # Display the results
    print("\nExtracted Threat Intelligence Data:")
    print(json.dumps(result, indent=4))

    # Ask user if they want to save the results
    save_choice = input("\nDo you want to save the results as a JSON file? (Y/N): ").strip().lower()
    if save_choice == 'y':
        save_to_json(result)
    else:
        print("Results not saved.")

if __name__ == "__main__":
    cli_frontend()