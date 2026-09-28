import os
import threading
import webbrowser
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
from backend.api import scan, crypto_lab

# Initialize database tables
init_db()

app = FastAPI(
    title="Mobile Security & Cryptographic Vulnerability Analyzer",
    description="Automated static security analysis platform for Android APKs with cryptographic focus.",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(scan.router)
app.include_router(crypto_lab.router)

frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

@app.get("/", include_in_schema=False)
def home():
    return FileResponse(os.path.join(frontend_dir, "landing.html"))

# Serve Frontend Static Files
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:8000/")).start()
    uvicorn.run(app, host="127.0.0.1", port=8000)
