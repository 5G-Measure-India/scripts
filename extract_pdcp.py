import os
import sys

def extract_pdcp_ul_stats(file_path):
    """
    Extract packets containing "PDCP UL Stats" in their opening line from a 5G NR dump file.
    
    Args:
        file_path (str): Path to the 5G NR dump file
        
    Returns:
        list: List of packets (as strings) containing "PDCP UL Stats" in their opening line
    """
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        return []
    
    try:
        # Read the file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            data = file.read()
        
        # Split the data into packets using empty lines as separators
        packets = data.split("\n\n")
        
        # Filter packets that have "PDCP UL Stats" in their first line
        pdcp_ul_stats_packets = []
        for i in range(len(packets) - 1):
            packet = packets[i]
            if packet.strip():  # Ensure packet is not empty
                lines = packet.strip().split("\n")
                if lines and "PDCP UL Stats" in lines[0]:
                    pdcp_ul_stats_packets.append(packets[i] + '\n' + packets[i+1] + '\n' + packets[i+2])
        
        return pdcp_ul_stats_packets
    
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def main():
    # Check if file path is provided as command line argument
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        # Prompt user for file path if not provided as command line argument
        file_path = input("Enter the path to the 5G NR dump file: ")
    
    pdcp_ul_packets = extract_pdcp_ul_stats(file_path)
    
    if pdcp_ul_packets:
        print(f"Found {len(pdcp_ul_packets)} packets containing 'PDCP UL Stats'")
        
        # Save the extracted packets to an output file
        output_file = "pdcp_ul_stats.txt"
        with open(output_file, 'w', encoding='utf-8') as out_file:
            for i, packet in enumerate(pdcp_ul_packets, 1):
                out_file.write(f"{packet}\n\n{'='*80}\n\n")
        
        print(f"Extracted packets saved to '{output_file}'")
    else:
        print("No packets containing 'PDCP UL Stats' found in the file.")

if __name__ == "__main__":
    main()
