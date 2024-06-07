#!/usr/bin/bash
# Bash Script to Analyze Network Traffic

# Check for tshark
if ! command -v tshark >/dev/null 2>&1; then
  # tshark not found, attempt installation
  echo "tshark not found, attempting installation..."
  if [ "$(uname)" == "Linux" ]; then
    sudo apt-get install tshark  
  else
    echo "Unsupported system, manual installation of tshark might be required."
  fi

  # Check if installation was successful 
  if command -v tshark >/dev/null 2>&1; then
    echo "tshark installed successfully, re-running script..."
    # Call the script itself recursively to restart with tshark available
    sh "$0"
  else
    echo "Failed to install tshark, script cannot proceed."
    exit
  fi
fi

# Input: Path to the Wireshark pcap file
pcap_file=$1 # capture input from terminal.
# Function to extract information from the pcap file
analyze_traffic() {
    
    TotalPackets=$(tshark -r "$pcap_file" -qz io,phs | awk 'NR==6' | awk '{print $2}' | awk -F ':' '{print $2}')
    #Different Method -> TotalPackets=$(tcpdump -r "$pcap_file" | wc -l)
    
    httpPackets=$(tshark -r "$pcap_file" -qz io,phs | grep "http" | head -n 1| awk '{print $2}' | awk -F ':' '{print $2}')
    #Different Method -> httpPackets=$(tshark -r "$pcap_file" -Y "http" | wc -l)

    tlsPackets=$(tshark -r "$pcap_file" -qz io,phs | grep "tls" |head -n 1| awk '{print $2}' | awk -F ':' '{print $2}')
    #Different Method -> tlsPackets=$(tshark -r "$pcap_file" -Y "tls" | wc -l)


    #------------------
    # Output analysis summary
    echo "----- Network Traffic Analysis Report -----"
    # Provide summary information based on your analysis
    echo "1. Total Packets: $TotalPackets"

    echo "2. Protocols:"
    echo "   - HTTP: $httpPackets packets"
    echo "   - HTTPS/TLS: $tlsPackets packets"
    
    echo ""
    echo "3. Top 5 Source IP Addresses:"
    Top5IpSrc=$(tshark -r "$pcap_file" -T fields -e ip.src | sort | uniq -c | sort -nr |head -n 5 )
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip_src=$(echo "$line" | awk '{print $2}')
        echo "   -$ip_src   :   $count  packets"
    done <<< "$Top5IpSrc"
    
    echo ""
    echo "4. Top 5 Destination IP Addresses:"
    Top5IpDst=$(tshark -r "$pcap_file" -T fields -e ip.dst | sort | uniq -c | sort -nr |head -n 5 )
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip_dst=$(echo "$line" | awk '{print $2}')
        echo "   -$ip_dst   :   $count packets"
    done <<< "$Top5IpDst"
   
    echo ""
    echo "----- End of Report -----"
}


# Run the analysis function
if [ -f "$1" ]; then
    analyze_traffic
else
    echo "File: '$1' doesn't exist"
fi
