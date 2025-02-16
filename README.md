# ReconHive

## Overview
ReconHive is an all-in-one network mapping and security reconnaissance tool with a web interface. It integrates **Nmap, Masscan, Nikto, Metasploit, and Sn1per** to provide a seamless experience for security professionals and researchers.

## Features
- 🔍 **Network Scanning** with Nmap & Masscan
- 🌐 **Web Vulnerability Scanning** using Nikto
- 🐝 **Automated Reconnaissance** using Sn1per
- 📊 **Web Dashboard** for easy control & results visualization
- 🚀 **One-Command Deployment** via Docker

## Installation
ReconHive is designed for **quick deployment using Docker**.

### Prerequisites
Ensure you have **Docker** installed on your system.

### Deploy with Docker
```bash
docker pull your-dockerhub/reconhive

docker run -d -p 5000:5000 -p 3000:3000 your-dockerhub/reconhive
```

Once running, access the web UI at:
```
http://localhost:3000
```

## Usage
1. **Start a scan** by entering a target in the web UI.
2. **Choose your tools** (Nmap, Masscan, Nikto, etc.).
3. **View results** in real-time with detailed reports.
4. **Analyze and export findings** for further investigation.

## License
This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License**.

🚫 **Commercial use and redistribution are strictly prohibited.**

For details, see the [LICENSE](LICENSE) file.

## Contributing
We welcome contributions! Feel free to submit a PR or open an issue to improve ReconHive.

