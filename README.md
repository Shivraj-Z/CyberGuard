
# CyberGuard: Multi-Utility Cybersecurity Toolkit

This project combines a React frontend (Material-UI based) with a Flask backend to provide essential cybersecurity tools like Password Strength Checking, Phishing URL Detection (using VirusTotal), and Basic Encryption.

## 🔧 Project Structure
```
CyberGuard/
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   └── React project (Material-UI)
└── README.md
```

## 🚀 Setup Instructions

### Backend (Flask)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set your VirusTotal API key in app.py
export FLASK_APP=app.py
flask run  # Runs on http://localhost:5000
```

### Frontend (React + MUI)
```bash
cd frontend
npm install @mui/material @emotion/react @emotion/styled axios
npm start  # Runs on http://localhost:3000
```

## 📡 API Communication
React frontend communicates via REST APIs with Flask backend hosted at `localhost:5000`.

Example APIs:
- POST `/check_password`
- POST `/check_url`
- POST `/encrypt_text`

## 🌐 Deployment
- **Backend:** Deploy via Render, Heroku, PythonAnywhere.
- **Frontend:** Deploy using Netlify, Vercel, or GitHub Pages (after building using `npm run build`).

## 🤝 Contributions
Open for community improvements and future feature additions.

## 📜 License
MIT License
