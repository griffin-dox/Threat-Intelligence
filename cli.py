import os
import json
import sys
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
    print("  -r : Extract Threat Actors")
    print("  -e : Extract Targeted Entities")
    print("  Example: 'i,m,t' to extract IoCs, Malware, and TTPs")
    print("  Type 'exit' to quit the program.")
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
    try:
        while True:
            display_logo()
            display_menu()

            # Take PDF file input
            pdf_path = input("Enter the path to the PDF file (or type 'exit' to quit): ").strip()
            if pdf_path.lower() == "exit":
                print("Exiting program. Goodbye!")
                sys.exit()

            if not os.path.exists(pdf_path):
                print("Error: File not found. Please check the path and try again.")
                continue

            # Ask user for extraction options
            print("\nSelect the type of intelligence to extract:")
            print("  [A] All")
            print("  [I] Indicators of Compromise (IoCs)")
            print("  [M] Malware Details")
            print("  [T] Tactics, Techniques, and Procedures (TTPs)")
            print("  [R] Threat Actors")
            print("  [E] Targeted Entities")
            print("  (Example: 'I,M,T' or 'A')")
            choice = input("Enter your choice: ").strip().lower()

            if choice == "exit":
                print("Exiting program. Goodbye!")
                sys.exit()

            # Parse user choices
            options = {
                'all': 'a' in choice,
                'iocs': 'i' in choice,
                'malware': 'm' in choice,
                'ttps': 't' in choice,
                'actors': 'r' in choice,
                'entities': 'e' in choice
            }
            
            # If 'a' is selected, enable everything
            if options['all']:
                options = {key: True for key in options}

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

            # Ask if they want to process another PDF
            another = input("\nDo you want to process another PDF? (Y/N): ").strip().lower()
            if another != 'y':
                print("Exiting program. Goodbye!")
                sys.exit()
    
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting gracefully. Goodbye!")
        sys.exit()

if __name__ == "__main__":
    cli_frontend()
