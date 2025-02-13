# Packet Sniffer Program in C++

This program is a packet sniffer written in C++ that demonstrates Object-Oriented Programming (OOP) concepts. The sniffer is capable of:

1. Capturing network packets from a specified network interface.
2. Digesting and displaying details of IP packets.
3. Analyzing the TCP, UDP, and ICMP protocols.
4. Analyzing HTTP, DNS, and FTP application layer protocols using multiple levels of inheritance.
5. Filtering captured packets based on a specific IP address and port.
6. Saving the captured packets to a file and allowing it to be opened with Wireshark or similar programs.

### Features

- **Capture IP Packets**: The program can capture and display information about IP packets, including their source and destination addresses.
- **TCP, UDP, and ICMP Protocols**: The sniffer can decode and display details of the TCP, UDP, and ICMP layers from the captured packets.
- **Application Layer Protocols**: It supports decoding HTTP, DNS, and FTP protocols in the application layer using multi-level inheritance in C++.
- **Packet Filtering**: You can filter packets based on IP and port using command-line options.
- **Packet Saving**: The program can save captured packets into a pcap file, which can be opened by tools like Wireshark.

### Program Structure

This program uses Object-Oriented Programming (OOP) principles and divides the code into different classes that represent various layers of the packet structure:

1. **Packet Class**: A base class for all types of packets. It includes methods for capturing packets and displaying basic information.
2. **IPPacket Class**: Inherits from `Packet` and handles parsing and displaying IP packet-specific fields (source/destination IP, etc.).
3. **TransportLayer Class**: A parent class for transport protocols like TCP and UDP.
4. **TCPPacket Class**: Inherits from `TransportLayer` and decodes TCP-specific fields.
5. **UDPPacket Class**: Inherits from `TransportLayer` and decodes UDP-specific fields.
6. **ICMPPacket Class**: Inherits from `Packet` and decodes ICMP-specific fields.
7. **ApplicationLayer Class**: A base class for application layer protocols like HTTP, DNS, and FTP.
8. **HTTPPacket, DNSPacket, FTPPacket Classes**: Inherit from `ApplicationLayer` and parse their respective application data.
9. **Sniffer Class**: Responsible for managing the capture process, applying filters, and saving packets to a file.

### Requirements

- **libpcap**: The program uses libpcap to capture packets from the network interface.
- **C++ Compiler**: Ensure that you have a C++ compiler such as `g++` installed.
- **Wireshark**: For opening the saved pcap files.

### Building the Program

To build the program, follow these steps:

1. **Install libpcap**: Make sure `libpcap` is installed on your system.

   On Linux:
   ```bash
   sudo apt-get install libpcap-dev
   ```

2. **Compile the program**:
   ```bash
   g++ -o sniffer main.cpp sniffer.cpp -lpcap
   ```

3. **Run the program**:
   To run the program, use the following command syntax:
   ```bash
   ./sniffer <interface> <filter_ip> <filter_port> <output_file>
   ```

   - `<interface>`: Network interface to capture packets from (e.g., `eth0`, `wlan0`).
   - `<filter_ip>`: The IP address to filter packets by.
   - `<filter_port>`: The port number to filter packets by.
   - `<output_file>`: The file to save the captured packets in pcap format.

   Example:
   ```bash
   ./sniffer eth0 192.168.1.100 80 capture.pcap
   ```

### Class Descriptions and Flow

#### 1. **Packet Class**
- This is the base class for all packets. It is responsible for capturing and displaying general packet information.
- **Methods**:
  - `capture_packet()`: Captures packets from the network interface.
  - `display_basic_info()`: Displays basic packet info (timestamp, packet size, etc.).

#### 2. **IPPacket Class**
- Inherits from `Packet` and adds functionality specific to IP packets.
- **Methods**:
  - `parse_ip()`: Parses the source and destination IP addresses from the packet.
  - `display_ip_info()`: Displays IP-specific information like source and destination IPs.

#### 3. **TransportLayer Class**
- A base class for transport layer protocols like TCP and UDP.
- **Methods**:
  - `parse_transport_layer()`: Decodes the transport layer header (TCP/UDP).
  - `display_transport_info()`: Displays transport layer details (e.g., port numbers).

#### 4. **TCPPacket Class**
- Inherits from `TransportLayer` and adds functionality specific to the TCP protocol.
- **Methods**:
  - `parse_tcp()`: Parses the TCP header (sequence number, flags, etc.).
  - `display_tcp_info()`: Displays TCP-specific information.

#### 5. **UDPPacket Class**
- Inherits from `TransportLayer` and adds functionality specific to the UDP protocol.
- **Methods**:
  - `parse_udp()`: Parses the UDP header (source and destination ports).
  - `display_udp_info()`: Displays UDP-specific information.

#### 6. **ICMPPacket Class**
- Inherits from `Packet` and decodes ICMP-specific information.
- **Methods**:
  - `parse_icmp()`: Parses ICMP headers (e.g., type, code).
  - `display_icmp_info()`: Displays ICMP-specific fields.

#### 7. **ApplicationLayer Class**
- A base class for application layer protocols like HTTP, DNS, and FTP.
- **Methods**:
  - `parse_application_data()`: Extracts and decodes application layer data.
  - `display_application_info()`: Displays relevant application layer information.

#### 8. **HTTPPacket, DNSPacket, FTPPacket Classes**
- These classes inherit from `ApplicationLayer` and decode the specific application protocols.
- **Methods**:
  - `parse_http()`: Decodes HTTP request/response headers.
  - `parse_dns()`: Decodes DNS query/response.
  - `parse_ftp()`: Decodes FTP commands/responses.

#### 9. **Sniffer Class**
- The main class that manages the packet capture process and applies filters.
- **Methods**:
  - `start_capture()`: Starts capturing packets.
  - `apply_filters()`: Applies filters based on IP and port.
  - `save_to_file()`: Saves captured packets to a pcap file.

### Example Flow

1. The user runs the program with the desired network interface, filter IP, and filter port.
2. The `Sniffer` class initializes the capture on the specified network interface.
3. The `Packet` class captures each packet from the network and processes it according to its type (IP, TCP, UDP, ICMP, etc.).
4. Each protocol (TCP, UDP, ICMP) class decodes the relevant fields from the packet and displays them.
5. If the packet matches the user-defined filter (IP and port), it is saved to the capture file.
6. The capture process continues until the user stops it, after which the program saves the capture data to the specified file.

basel@basel-Lenovo-ideapad-520-15IKB:~/demo$ sudo ./wirefish -i wlp3s0 -f "udp port 53"

Packet captured (89 bytes)
IP: 192.168.1.11 -> 192.168.1.1 TTL:64
UDP: 41737 -> 53
DNS: ID=3565 Questions=1

Packet captured (89 bytes)
IP: 192.168.1.11 -> 192.168.1.1 TTL:64
UDP: 32903 -> 53
DNS: ID=62920 Questions=1

Packet captured (105 bytes)
IP: 192.168.1.1 -> 192.168.1.11 TTL:64
UDP: 53 -> 41737
DNS: ID=3565 Questions=1

Packet captured (114 bytes)
IP: 192.168.1.1 -> 192.168.1.11 TTL:64
UDP: 53 -> 32903
DNS: ID=62920 Questions=1



### Saving and Viewing Packets

- After capturing packets, the program can save them to a `.pcap` file using `save_to_file()`.
- To view the saved packets, you can open the `.pcap` file in tools like **Wireshark**.
