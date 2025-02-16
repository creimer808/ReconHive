from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import subprocess
import shlex
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace this with a secure key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'  # Path to the SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database model for storing scan results
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    verbose_output = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f'<Scan {self.id} - {self.target_ip}>'

# Define expanded scan options with verbose flag added
SCAN_OPTIONS = {
    "-sn -v": "Ping Scan (Check if host is online) - Verbose",
    "-T4 -F -v": "Quick Scan (Fast scan of common ports) - Verbose",
    "-T4 -A -v -v": "Intense Scan (Aggressive with version detection) - Verbose",
    "-p- -v": "Full Port Scan (Scan all 65,535 ports) - Verbose",
    "-O -v": "OS Detection (Determine the OS) - Verbose",
    "-sV -v": "Service & Version Detection (Identify running services) - Verbose",
    "-sS -p 80,443,22 -T4 -v": "CTF Scan (Common Web and SSH Ports) - Verbose",
    "-sV --script=vuln -v": "Penetration Testing Scan (Vulnerability Scripts) - Verbose",
    "-sS -p 80,443 --script=http-vuln* -v": "Covert Scan (Using HTTP Vulnerability Scripts) - Verbose",
    "-O --script=discovery -v": "Discovery Scan (OS and Service Enumeration) - Verbose",
    "--script=http-title -v": "Simple Web Scan (Detect HTTP title and version) - Verbose",
    "--script=ssl-heartbleed -v": "SSL Vulnerability Scan (Heartbleed) - Verbose"
}

MASSCAN_OPTIONS = {
    "-p80 192.168.1.0/24": "Basic Scan (Port 80) - Subnet",
    "-p1-65535 192.168.1.0/24 --rate=1000": "Full Port Scan (All Ports, Rate 1000) - Subnet",
    "--rate=500 192.168.1.0/24": "Rate Limiting (Rate 500) - Subnet",
    "-p80,443,8080 192.168.1.0/24": "Multiple Ports (80, 443, 8080) - Subnet",
    "--exclude=192.168.1.100,192.168.1.101 192.168.1.0/24": "Exclude IPs (100, 101) - Subnet",
    "--include=192.168.1.1,192.168.1.2 -p80": "Include IPs (1, 2) - Port 80",
    "-p53 --rate=500 192.168.1.0/24": "Scan Specific Protocol (DNS on Rate 500) - Subnet"
}

@app.context_processor
def inject_request():
    return dict(request=request)


# Home route
@app.route('/')
def index():
    return render_template('home.html')


# Masscan functionality
@app.route('/masscan', methods=['GET', 'POST'])
def masscan_index():
    if request.method == 'POST':
        target_subnet = request.form.get('target_subnet')
        ports = request.form.get('ports')
        rate = request.form.get('rate')

        # Define the output file path
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_file = f"masscan_results_{timestamp}.txt"

        # Construct the Masscan command
        masscan_command = [
            "sudo",
            "masscan",
            target_subnet,
            "--rate", rate,
            "-p", ports,
            "-oN", output_file
        ]

        try:
            # Execute the Masscan command
            subprocess.run(masscan_command, check=True)
            
            # Capture the scan output from the file
            with open(output_file, 'r') as f:
                masscan_output = f.read()
            
            # Create the scan record
            new_scan = ScanHistory(target_ip=target_subnet, scan_type='masscan', 
                                   scan_output=masscan_output, verbose_output='', timestamp=datetime.datetime.utcnow())
            db.session.add(new_scan)
            db.session.commit()
            # Pass the new scan object to results page
            return render_template('masscan/results.html', scan=new_scan)
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('masscan_index'))  # Ensure this redirects correctly to Masscan index
    return render_template('masscan/index.html', masscan_options=MASSCAN_OPTIONS)

@app.route('/masscan/history')
def masscan_history():
    scans = ScanHistory.query.filter_by(scan_type='masscan').order_by(ScanHistory.timestamp.desc()).all()
    return render_template('masscan/history.html', scans=scans)

@app.route('/masscan/view_result/<int:scan_id>')
def masscan_view_result(scan_id):
    scan = ScanHistory.query.get(scan_id)
    if not scan:
        flash('Scan record not found.')
        return redirect(url_for('masscan_history'))
    return render_template('masscan/results.html', scan=scan)

@app.route('/masscan/delete_scan/<int:scan_id>', methods=['POST'])
def masscan_delete_scan(scan_id):
    scan_to_delete = ScanHistory.query.get(scan_id)
    if scan_to_delete:
        db.session.delete(scan_to_delete)
        db.session.commit()
        flash('Scan record deleted successfully.')
    else:
        flash('Scan record not found.')
    return redirect(url_for('masscan_history'))

# Nmap functionality
@app.route('/nmap', methods=['GET', 'POST'])
def nmap_index():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        scan_type = request.form.get('scan_type')
        custom_command = request.form.get('custom_command')

        if not target_ip:
            flash("Please enter an IP address.")
            return redirect(url_for('nmap_index'))

        try:
            # Handle custom command
            if scan_type == "custom":
                if not custom_command:
                    flash("Please enter a custom Nmap command.")
                    return redirect(url_for('nmap_index'))
                custom_args = shlex.split(custom_command)
            else:
                custom_args = shlex.split(scan_type)

            # Prepare the Nmap command with verbose flag
            nmap_command = ['nmap'] + custom_args + [target_ip]

            # Run Nmap and capture both stdout and stderr for verbose output
            result = subprocess.run(nmap_command, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)

            # Capture verbose output (stderr) and scan results (stdout)
            verbose_output = result.stderr
            nmap_output = result.stdout

            if result.returncode != 0:
                flash("Nmap command failed.")
                return redirect(url_for('nmap_index'))  # Redirect to Nmap index

            # Create the scan record
            new_scan = ScanHistory(target_ip=target_ip, scan_type='nmap', 
                                   scan_output=nmap_output, verbose_output=verbose_output)
            db.session.add(new_scan)
            db.session.commit()

            # Pass the new scan object to results page
            return render_template('nmap/results.html', scan=new_scan)

        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('nmap_index'))  # Ensure this redirects correctly to Nmap

    return render_template('nmap/index.html', scan_options=SCAN_OPTIONS)

@app.route('/nmap/history')
def nmap_history():
    scans = ScanHistory.query.filter_by(scan_type='nmap').order_by(ScanHistory.timestamp.desc()).all()
    return render_template('nmap/history.html', scans=scans)

@app.route('/nmap/view_result/<int:scan_id>')
def nmap_view_result(scan_id):
    scan = ScanHistory.query.get(scan_id)
    if not scan:
        flash('Scan record not found.')
        return redirect(url_for('nmap_history'))
    return render_template('nmap/results.html', scan=scan)

@app.route('/nmap/delete_scan/<int:scan_id>', methods=['POST'])
def nmap_delete_scan(scan_id):
    scan_to_delete = ScanHistory.query.get(scan_id)
    if scan_to_delete:
        db.session.delete(scan_to_delete)
        db.session.commit()
        flash('Scan record deleted successfully.')
    else:
        flash('Scan record not found.')
    return redirect(url_for('nmap_history'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True, host='0.0.0.0')
