# Port Scanner

A simple Python-based TCP port scanner that allows you to scan one or more target IP addresses or domain names for open ports within a specified range. This tool provides information about open ports, including service banners and potential vulnerabilities.

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Purpose](#purpose)

## Features

- Scan one or more target IP addresses or domain names for open ports.
- Specify a port range to scan or scan all available ports.
- Retrieve service banners and service versions for open ports.
- Detect known vulnerabilities for specific services (e.g., FTP, SSH).
- Multithreaded scanning for faster results.
- Save scan results to a JSON file.
- Optional verbose output.

## Tech Stack

This project is built using the following technologies and Python libraries:

- Python 3.x: The core programming language used for development.
- [argparse](https://docs.python.org/3/library/argparse.html): Python library for parsing command-line arguments.
- [socket](https://docs.python.org/3/library/socket.html): Python library for low-level network programming.
- [threading](https://docs.python.org/3/library/threading.html): Python library for multithreading.
- [json](https://docs.python.org/3/library/json.html): Python library for working with JSON data.
- [tqdm](https://github.com/tqdm/tqdm): Python library for displaying progress bars.
- [termcolor](https://pypi.org/project/termcolor/): Python library for adding color to terminal text.
- [IPython](https://ipython.org/): Interactive computing in Python (for interactive use, not required for the core functionality).

These libraries and tools are used to create a robust and efficient port scanning utility that simplifies the process of identifying open ports and gathering information about the services running on them.


## Getting Started

### Prerequisites

- Python 3.x
- pip (Python package manager)

### Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/pannagkumaar/PortScanner.git
  
2. Navigate to the project directory:
   ```shell  
   cd port-scanner
3. Install the required Python packages:
   ```shell
   pip install -r requirements.txt 
## Usage    
```bash
python port_scanner.py -t <targets> [-p <port-range>] [-T <timeout>] [-n <num-threads>] [-o <output>] [-v]
```
## Options   
- -t, --targets: Specify the target IP addresses or domain names (required).
- -p, --port-range: Specify the port range to scan (e.g., 1-100 or all). Default is 1-100.
- -T, --timeout: Specify the timeout value in seconds. Default is 1.0 seconds.
- -n, --num-threads: Specify the number of threads to use for scanning. Default is 10.
- -o, --output: Specify an output file to save results to (e.g., output.json).
- -v, --verbose: Enable verbose output.

## Examples
1. Scan a single target for open ports (default port range):
 ```shell
 python port_scanner.py -t 192.168.1.1
 ```
2. Scan multiple targets with a custom port range and save results to a file:
```shell
 python port_scanner.py -t example.com 192.168.1.1 -p 1-65535 -o results.json
``` 
3. Enable verbose output:
```shell
python port_scanner.py -t 192.168.1.1 -v
```
## Purpose

The purpose of this project is to provide a simple yet effective TCP port scanning tool that allows users to scan one or more target IP addresses or domain names for open ports. It is designed to be versatile, fast, and informative, providing essential information about open ports, service banners, and potential vulnerabilities. Whether you are a network administrator, a security professional, or a curious individual, this tool can help you identify open ports on your network and gather valuable insights about the services running on them.
