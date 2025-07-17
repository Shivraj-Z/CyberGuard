
import React, { useState } from 'react';
import axios from 'axios';
import { Button, TextField, Typography, Container, Card, CardContent } from '@mui/material';

function App() {
  const [password, setPassword] = useState('');
  const [passwordResult, setPasswordResult] = useState('');
  const [url, setUrl] = useState('');
  const [urlResult, setUrlResult] = useState({});
  const [text, setText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');

  const backendUrl = 'http://localhost:5000';

  const checkPassword = async () => {
    const res = await axios.post(`${backendUrl}/check_password`, { password });
    setPasswordResult(res.data.strength);
  };

  const checkURL = async () => {
    const res = await axios.post(`${backendUrl}/check_url`, { url });
    setUrlResult(res.data);
  };

  const encryptText = async () => {
    const res = await axios.post(`${backendUrl}/encrypt_text`, { text });
    setEncryptedText(res.data.encrypted);
  };

  const ModuleCard = ({ title, children }) => (
    <Card sx={{ marginBottom: 4, boxShadow: 3, borderRadius: 3 }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>{title}</Typography>
        {children}
      </CardContent>
    </Card>
  );

  return (
    <Container maxWidth="sm" sx={{ marginTop: 4 }}>
      <Typography variant="h3" align="center" gutterBottom>
        CyberGuard Toolkit
      </Typography>

      <ModuleCard title="Password Strength Checker">
        <TextField label="Enter password" fullWidth margin="normal" value={password} onChange={e => setPassword(e.target.value)} />
        <Button variant="contained" onClick={checkPassword} fullWidth>Check Strength</Button>
        <Typography variant="body1" sx={{ marginTop: 1 }}>Strength: {passwordResult}</Typography>
      </ModuleCard>

      <ModuleCard title="Phishing URL Checker">
        <TextField label="Enter URL" fullWidth margin="normal" value={url} onChange={e => setUrl(e.target.value)} />
        <Button variant="contained" onClick={checkURL} fullWidth>Check URL</Button>
        <Typography variant="body1" sx={{ marginTop: 1 }}>Heuristic: {urlResult.heuristic}</Typography>
        <Typography variant="body1">VirusTotal: {urlResult.virustotal}</Typography>
      </ModuleCard>

      <ModuleCard title="Text Encryptor">
        <TextField label="Enter text" fullWidth margin="normal" value={text} onChange={e => setText(e.target.value)} />
        <Button variant="contained" onClick={encryptText} fullWidth>Encrypt Text</Button>
        <Typography variant="body1" sx={{ marginTop: 1 }}>Encrypted: {encryptedText}</Typography>
      </ModuleCard>

    </Container>
  );
}

export default App;
