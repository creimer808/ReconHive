import React from 'react';
import axios from 'axios';

function App() {
  const [networkScanResult, setNetworkScanResult] = React.useState('');
  const [webScanResult, setWebScanResult] = React.useState('');

  async function handleNetworkScan(target) {
    try {
      const response = await axios.post('http://localhost:5000/scan/network', { target });
      setNetworkScanResult(response.data.output);
    } catch (error) {
      console.error(error);
    }
  }

  async function handleWebScan(target) {
    try {
      const response = await axios.post('http://localhost:5000/scan/web', { target });
      setWebScanResult(response.data.output);
    } catch (error) {
      console.error(error);
    }
  }

  return (
    <div className="App">
      <h1>Recon Tool</h1>
      <input type="text" placeholder="Enter network target" onChange={(e) => handleNetworkScan(e.target.value)} />
      <pre>{networkScanResult}</pre>

      <input type="text" placeholder="Enter web target (hostname)" onChange={(e) => handleWebScan(e.target.value)} />
      <pre>{webScanResult}</pre>
    </div>
  );
}

export default App;
