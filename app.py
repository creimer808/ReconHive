from flask import Flask, render_template, request, redirect, url_for, flash
import subprocess

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace this with a secure key in production

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        
        if not target_ip:
            flash("Please enter an IP address.")
            return redirect(url_for('index'))
        
        try:
            # Run Nmap command
            result = subprocess.run(['nmap', '-Pn', '-', '-A', target_ip], 
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
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
