from fastapi import FastAPI, HTTPException
import subprocess
import json

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/scan/network")
async def scan_network(target: str):
    try:
        result = subprocess.run(['nmap', target], capture_output=True)
        output = result.stdout.decode('utf-8')
        # You can parse and format the output as needed
        return {"status": "success", "output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/web")
async def scan_web(target: str):
    try:
        result = subprocess.run(['nikto', '-host', target], capture_output=True)
        output = result.stdout.decode('utf-8')
        # You can parse and format the output as needed
        return {"status": "success", "output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
