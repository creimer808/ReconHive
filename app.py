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
            # Handle custom command
            if scan_type == "custom":
                if not custom_command:
                    flash("Please enter a custom Nmap command.")
                    return redirect(url_for('index'))
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

            # If Nmap fails, show error and redirect
            if result.returncode != 0:
                flash("Nmap command failed.")
                return redirect(url_for('index'))

            # Create the scan record
            new_scan = ScanHistory(target_ip=target_ip, scan_type=scan_type, 
                                   scan_output=nmap_output, verbose_output=verbose_output)
            db.session.add(new_scan)
            db.session.commit()

            # Pass the new scan object to results page
            return render_template('results.html', scan=new_scan)

        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('index'))

    return render_template('index.html', scan_options=SCAN_OPTIONS)


@app.route('/history')
def history():
    # Fetch all scan history records from the database
    scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/view_result/<int:scan_id>')
def view_result(scan_id):
    # Fetch the specific scan record from the database
    scan = ScanHistory.query.get(scan_id)

    if not scan:
        flash('Scan record not found.')
        return redirect(url_for('history'))

    # Pass the scan details to the results page
    return render_template('results.html', scan=scan)

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    # Delete a specific scan record from the database
    scan_to_delete = ScanHistory.query.get(scan_id)
    if scan_to_delete:
        db.session.delete(scan_to_delete)
        db.session.commit()
        flash('Scan record deleted successfully.')
    else:
        flash('Scan record not found.')
    return redirect(url_for('history'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True, host='0.0.0.0')
