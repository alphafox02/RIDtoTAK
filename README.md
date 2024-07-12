# RIDtoTAK

This project processes Remote ID (RID) data from drones and sends it as Cursor on Target (CoT) messages to a TAK server. It integrates with the Sniffle tool to capture Bluetooth packets.

## Prerequisites

1. Python 3.6 or later
2. Wireshark and TShark
3. `mkfifo` utility
4. `sniff_receiver` from the [Sniffle](https://github.com/nccgroup/Sniffle) repository

## Setup Instructions

### Step 1: Clone the RIDtoTAK Repository
git clone https://github.com/yourusername/RIDtoTAK.git
cd RIDtoTAK


### Step 2: Set Up FIFO for Drone PCAP

In a separate terminal window, create a FIFO for the drone PCAP:
mkfifo /tmp/drone_pcap


### Step 3: Clone and Set Up Sniffle

In another terminal window, clone the Sniffle repository and run the `sniff_receiver` tool:
git clone https://github.com/nccgroup/Sniffle.git
cd Sniffle/python_cli
./sniff_receiver -l -e -o /tmp/drone_pcap


### Step 4: Run RIDtoTAK

Back in the `RIDtoTAK` directory, run the RIDtoTAK script. Adjust the `--tak-host`, `--tak-port`, and `--fifo-pcap-path` parameters as needed:
python3 RIDtoTAK.py --tak-host 0.0.0.0 --tak-port 8054 --update-interval 5 --fifo-pcap-path /tmp/drone_pcap

## Parameters

- `--tak-host`: TAK server hostname or IP address.
- `--tak-port`: TAK server port.
- `--update-interval`: Interval in seconds for CoT message updates.
- `--fifo-pcap-path`: Path to the FIFO PCAP file.

## Example Command
python3 RIDtoTAK.py --tak-host 192.168.1.100 --tak-port 8087 --update-interval 10 --fifo-pcap-path /tmp/drone_pcap
