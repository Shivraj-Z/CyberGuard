
from flask import Flask, render_template, request, jsonify
import requests
import base64
import os

app = Flask(__name__)

# Optional: Set your VirusTotal API Key here
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    password = request.json.get('password', '')
    strength = 'Weak'
    if len(password) >= 12 and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(not c.isalnum() for c in password):
        strength = 'Strong'
    elif len(password) >= 8:
        strength = 'Moderate'
    return jsonify({'strength': strength})

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    suspicious_keywords = ['free', 'login', 'account', 'secure', 'bank']
    heuristic_result = 'Safe'
    for keyword in suspicious_keywords:
        if keyword in url:
            heuristic_result = 'Suspicious (Heuristic)'
            break

    # VirusTotal URL Scan
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    response = requests.get(vt_url, headers=headers)

    vt_result = 'Not Checked'
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        if stats.get('malicious', 0) > 0:
            vt_result = 'Malicious (VirusTotal)'
        else:
            vt_result = 'Clean (VirusTotal)'

    return jsonify({'heuristic': heuristic_result, 'virustotal': vt_result})

@app.route('/encrypt_text', methods=['POST'])
def encrypt_text():
    text = request.json.get('text', '')
    encrypted = base64.b64encode(text.encode()).decode()
    return jsonify({'encrypted': encrypted})

if __name__ == '__main__':
    app.run(debug=True)
