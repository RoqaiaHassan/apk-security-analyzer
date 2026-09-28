import os
import uuid
import shutil
import asyncio
from typing import Dict, Any, List
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse

from backend.analyzers.apk_parser import APKParser
from backend.analyzers.manifest import ManifestAnalyzer
from backend.analyzers.dex_analyzer import DexAnalyzer
from backend.analyzers.crypto_engine import CryptoEngine
from backend.analyzers.secrets_engine import SecretsEngine
from backend.analyzers.network_engine import NetworkEngine
from backend.analyzers.sig_analyzer import SignatureAnalyzer
from backend.detectors.rules_engine import RulesEngine
from backend.crypto.score import SecurityScoreCalculator
from backend.database import save_scan, get_all_scans, get_scan_by_id, delete_scan
from backend.reports.pdf_generator import PDFReportGenerator

router = APIRouter(prefix="/api", tags=["Analysis Engine"])

UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "uploads"))
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "reports_output"))

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

active_websockets: Dict[str, List[WebSocket]] = {}
scan_progress: Dict[str, Dict[str, Any]] = {}

async def broadcast_log(scan_id: str, message: str, stage: str, progress: int):
    if scan_id not in scan_progress:
        scan_progress[scan_id] = {"progress": 0, "stage": stage, "logs": []}
    
    scan_progress[scan_id]["progress"] = progress
    scan_progress[scan_id]["stage"] = stage
    scan_progress[scan_id]["logs"].append(message)

    if scan_id in active_websockets:
        dead_ws = []
        for ws in active_websockets[scan_id]:
            try:
                await ws.send_json({
                    "scan_id": scan_id,
                    "progress": progress,
                    "stage": stage,
                    "log": message
                })
            except Exception:
                dead_ws.append(ws)
        for ws in dead_ws:
            active_websockets[scan_id].remove(ws)

def run_apk_analysis_sync(scan_id: str, apk_path: str, original_filename: str):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    temp_extract_dir = os.path.join(UPLOAD_DIR, f"extract_{scan_id}")
    rules_engine = RulesEngine()

    try:
        loop.run_until_complete(broadcast_log(scan_id, "[10:20:01] Loading APK...", "Loading APK", 5))
        file_size = os.path.getsize(apk_path)
        hashes = APKParser.calculate_hashes(apk_path)
        loop.run_until_complete(broadcast_log(scan_id, f"[10:20:02] Calculated hashes: SHA256={hashes['sha256'][:16]}...", "Calculating Hashes", 15))

        loop.run_until_complete(broadcast_log(scan_id, "[10:20:03] Validating and Extracting APK files...", "Extracting APK", 25))
        extract_res = APKParser.validate_and_extract(apk_path, temp_extract_dir)
        loop.run_until_complete(broadcast_log(scan_id, f"[10:20:04] Extracted {extract_res['extracted_count']} files successfully.", "Extracted Files", 35))

        loop.run_until_complete(broadcast_log(scan_id, "[10:20:05] Parsing AndroidManifest.xml...", "Parsing AndroidManifest", 45))
        manifest_data = ManifestAnalyzer.parse_manifest(temp_extract_dir)

        loop.run_until_complete(broadcast_log(scan_id, "[10:20:06] Decompiling and analyzing bytecode string pool...", "Analyzing Source/Bytecode", 55))
        string_records = DexAnalyzer.extract_strings(temp_extract_dir)
        loop.run_until_complete(broadcast_log(scan_id, f"[10:20:07] Extracted {len(string_records)} string items for crypto & secret analysis.", "Bytecode Extraction Complete", 65))

        loop.run_until_complete(broadcast_log(scan_id, "[10:20:08] Running Cryptographic Security Engine...", "Cryptographic Analysis", 75))
        crypto_findings = CryptoEngine.analyze_crypto_usage(string_records)

        loop.run_until_complete(broadcast_log(scan_id, "[10:20:09] Running Secrets & Hardcoded Keys Detector...", "Secrets Detection", 82))
        secrets_findings = SecretsEngine.analyze_secrets(string_records)

        loop.run_until_complete(broadcast_log(scan_id, "[10:20:10] Running Network & Storage Security Engine...", "Network/Storage Analysis", 88))
        net_findings = NetworkEngine.analyze_network(string_records)

        sig_info = SignatureAnalyzer.analyze_signature(temp_extract_dir)

        # Merge findings
        all_findings = crypto_findings + secrets_findings + net_findings

        # Manifest specific permission & config findings
        if manifest_data["debuggable"]:
            all_findings.append({
                "rule_id": "RULE-016",
                "vulnerability": "Application is Debuggable",
                "severity": "High",
                "category": "Application Configuration",
                "algorithm": "N/A",
                "file": "AndroidManifest.xml",
                "line": 1,
                "evidence": 'android:debuggable="true"',
                "description": "Application manifest enables debuggable mode.",
                "status": "DETECTED"
            })

        for p in manifest_data["permissions"]:
            if any(danger in p for danger in ["CAMERA", "CONTACTS", "LOCATION", "RECORD_AUDIO", "SMS"]):
                all_findings.append({
                    "rule_id": "RULE-014",
                    "vulnerability": "Dangerous Android Permission Requested",
                    "severity": "High",
                    "category": "Permissions",
                    "algorithm": "N/A",
                    "file": "AndroidManifest.xml",
                    "line": 1,
                    "evidence": f"Permission requested: {p}",
                    "description": f"Dangerous permission detected: {p}",
                    "status": "DETECTED"
                })

        # Enrich findings with rules engine
        enriched_findings = [rules_engine.enrich_finding(f) for f in all_findings]

        # Calculate Security Score
        score_res = SecurityScoreCalculator.calculate(enriched_findings)

        loop.run_until_complete(broadcast_log(scan_id, f"[10:20:11] Analysis complete! Security Score: {score_res['security_score']}/100.", "Completed", 100))

        result_payload = {
            "id": scan_id,
            "app_name": manifest_data.get("package_name", "App").split(".")[-1].capitalize(),
            "package_name": manifest_data.get("package_name", "com.example.app"),
            "version_name": manifest_data.get("version_name", "1.0.0"),
            "file_name": original_filename,
            "file_size": file_size,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "security_score": score_res["security_score"],
            "counts": score_res["counts"],
            "category_scores": score_res["category_scores"],
            "manifest": manifest_data,
            "signature": sig_info,
            "findings": enriched_findings,
            "status": "COMPLETED"
        }

        save_scan(result_payload)

    except Exception as e:
        loop.run_until_complete(broadcast_log(scan_id, f"[ERROR] Analysis failed: {str(e)}", "Failed", 100))
    finally:
        if os.path.exists(temp_extract_dir):
            shutil.rmtree(temp_extract_dir, ignore_errors=True)

@router.post("/upload")
async def upload_apk(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are supported.")

    scan_id = str(uuid.uuid4())[:8]
    save_path = os.path.join(UPLOAD_DIR, f"{scan_id}_{file.filename}")

    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    if background_tasks:
        background_tasks.add_task(run_apk_analysis_sync, scan_id, save_path, file.filename)

    return {
        "scan_id": scan_id,
        "file_name": file.filename,
        "status": "ANALYSIS_STARTED"
    }

@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in active_websockets:
        active_websockets[scan_id] = []
    active_websockets[scan_id].append(websocket)

    # Replay past logs if available
    if scan_id in scan_progress:
        sp = scan_progress[scan_id]
        for log_msg in sp["logs"]:
            await websocket.send_json({
                "scan_id": scan_id,
                "progress": sp["progress"],
                "stage": sp["stage"],
                "log": log_msg
            })

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if scan_id in active_websockets and websocket in active_websockets[scan_id]:
            active_websockets[scan_id].remove(websocket)

@router.get("/scan/{scan_id}")
def get_scan_results(scan_id: str):
    res = get_scan_by_id(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return res

@router.get("/history")
def get_history():
    return get_all_scans()

@router.delete("/scan/{scan_id}")
def delete_scan_id(scan_id: str):
    deleted = delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    return {"status": "DELETED", "scan_id": scan_id}

@router.get("/report/{scan_id}")
def get_pdf_report(scan_id: str):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found.")

    pdf_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
    PDFReportGenerator.generate_pdf(scan_data, pdf_path)

    return FileResponse(pdf_path, media_type="application/pdf", filename=f"Mobile_Security_Report_{scan_id}.pdf")
