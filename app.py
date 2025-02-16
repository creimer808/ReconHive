from flask import Flask, render_template, request, redirect, url_for, flash
import subprocess

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace this with a secure key in production

# Define popular scan options
SCAN_OPTIONS = {
    "-sn": "Ping Scan (Check if host is online)",
    "-T4 -F": "Quick Scan (Fast scan of common ports)",
    "-T4 -A -v": "Intense Scan (Aggressive with version detection)",
    "-p-": "Full Port Scan (Scan all 65,535 ports)",
    "-O": "OS Detection (Determine the OS)",
    "-sV": "Service & Version Detection (Identify running services)"
}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        scan_type = request.form.get('scan_type')

        if not target_ip:
            flash("Please enter an IP address.")
            return redirect(url_for('index'))

        try:
            # Build Nmap command
            nmap_command = ['nmap'] + scan_type.split() + [target_ip]

            # Run Nmap
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
