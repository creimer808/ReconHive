# Import necessary modules
from flask import Flask, render_template, request, redirect, url_for, flash  # Flask for web framework
import subprocess  # To run external commands (like Nmap)
import shlex  # To safely split command strings into arguments

# Initialize the Flask app
app = Flask(__name__)

# Secret key for session management (needed by Flask for things like flashing messages)
app.secret_key = 'supersecretkey'  # In production, replace with a real secret key

# Define a dictionary for popular Nmap scan options
SCAN_OPTIONS = {
    "-sn": "Ping Scan (Check if host is online)",
    "-T4 -F": "Quick Scan (Fast scan of common ports)",
    "-T4 -A -v": "Intense Scan (Aggressive with version detection)",
    "-p-": "Full Port Scan (Scan all 65,535 ports)",
    "-O": "OS Detection (Determine the OS)",
    "-sV": "Service & Version Detection (Identify running services)",
    # Additional scans for CTFs, PenTesting, and Covert Scanning
    "-sS -p 80,443,22 -T4": "CTF Scan (Common Web and SSH Ports)",
    "-sV --script=vuln": "Penetration Testing Scan (Vulnerability Scripts)",
    "-sS -p 80,443 --script=http-vuln*": "Covert Scan (Using HTTP Vulnerability Scripts)",
    "-O --script=discovery": "Discovery Scan (OS and Service Enumeration)",
    "--script=http-title": "Simple Web Scan (Detect HTTP title and version)",
    "--script=ssl-heartbleed": "SSL Vulnerability Scan (Heartbleed)"
}

# Define the route for the home page, allowing both GET and POST requests
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        scan_type = request.form.get('scan_type')
        custom_command = request.form.get('custom_command')

        if not target_ip:
            flash("Please enter an IP address.")
            return redirect(url_for('index'))

        try:
            if scan_type == "custom":
                if not custom_command:
                    flash("Please enter a custom Nmap command.")
                    return redirect(url_for('index'))
                # Split the custom command into individual arguments
                custom_args = shlex.split(custom_command)
            else:
                custom_args = shlex.split(scan_type)

            # Prepare the full Nmap command with the target IP address
            nmap_command = ['nmap'] + custom_args + [target_ip]

            # Run the Nmap command using subprocess
            result = subprocess.run(nmap_command, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)

            if result.returncode != 0:
                flash("Nmap command failed.")
                return redirect(url_for('index'))

            nmap_output = result.stdout
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('index'))

        return render_template('results.html', output=nmap_output)
    
    return render_template('index.html', scan_options=SCAN_OPTIONS)

# If this script is run directly (i.e., not imported), start the Flask app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # Run the app in debug mode on all network interfaces
