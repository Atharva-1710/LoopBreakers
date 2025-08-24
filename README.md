🌐 Network Traffic Visualizer
Project Description
This project, developed as part of a hackathon, is a real-time network traffic visualizer. It builds a tool that captures and visualizes local network packets in real-time, displaying statistics such as protocol distribution (TCP vs. UDP counts) and connection flows, all within a simple graphical interface.

Features
Real-time Packet Capture: Captures network packets flowing through a selected network interface.

Dynamic Interface Selection: Allows users to choose which network adapter to monitor from a list of available interfaces.

Protocol Distribution: Visualizes the distribution of different network protocols (e.g., TCP, UDP, ICMP, ARP) using a pie chart.

Top Connection Flows: Identifies and displays the top network connections by data volume.

Basic Filtering: Includes a basic filter to show only specific types of packets (e.g., TCP only).

Live Packet Table: Displays a table of the most recently captured packets with details like timestamp, source/destination IPs, protocol, and size.

Start/Stop Functionality: Provides controls to initiate and pause packet capturing.

Administrator/Root Privilege Check: Ensures the application is run with necessary permissions for packet sniffing.

Tech Stack
Python: Primary programming language.

Rich : For Terminal Visualization

Scapy: (To be integrated) For robust packet capturing and parsing.

Pandas: For efficient data processing and manipulation of captured packet data.


Project Structure
LoopBreakers-P4/
├── core/
│   ├── __init__.py             # Initializes the core package
│   ├── packet_processor.py     # Contains functions for sniffing, parsing, and processing network packets
│   └── visualizer.py           # Contains functions for generating various data visualizations
├── Screenshot/                 # Directory for project screenshots
│   └── SS1.png                 # Screenshot of Output
├── utils/
│   ├── __init__.py             # Initializes the utils package
│   └── network_utils.py        # Contains utility functions like listing network interfaces and privilege checks
├── app.py                      # Main Streamlit application file, orchestrating the UI and logic
├── README.md                   # This documentation file
└── requirements.txt            # Lists all Python dependencies required to run the project

Installation and Setup
Clone the Repository:

git clone https://github.com/Atharva-1710/LoopBreakers-P4.git
cd LoopBreakers-P4

# On Windows:

Python should be Installed

Install Dependencies:

pip install -r requirements.txt

Important: Root/Administrator Privileges:
Packet capturing requires elevated privileges. You must run the application with administrator or root rights.

On Windows: Open your Command Prompt or PowerShell as an Administrator.

Enter : python -u "c:<the loaction where we have stored >\LoopBreakers-P4\app.py"

You will see the visualisation has initialized.

# On Windows (from Administrator PowerShell/CMD):

View Visualizations:
The main area of the application will display real-time updates of:

A table of recently captured packets.

Deliverables Checklist (Hackathon Specific)
 Source code (app.py, core/, utils/)

 Demo showing real-time visualization on your machine (achieved by running streamlit run app.py)

 Brief documentation (this README.md serves this purpose) explaining visualization approach and data presented.



