from pymongo import AsyncMongoClient
import os
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import tempfile, os, subprocess, re, uuid
from fastapi.concurrency import run_in_threadpool
import asyncio
from difflib import SequenceMatcher
from enum import Enum
from apkfile import ApkFile
from google_play_scraper import app as play_app 
from google_play_scraper import search
from dotenv import load_dotenv
from contextlib import asynccontextmanager
import json
import shutil
from datetime import datetime
import yara

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        await client.admin.command("ping")
        print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ Could not connect to MongoDB: {e}")
        raise RuntimeError("Database connection failed")
    yield
    # Shutdown
    client.close()
    print("👋 MongoDB connection closed")

app = FastAPI(lifespan=lifespan)


origins = [
    "http://localhost:3000",  # your frontend URL
    "https://fraudrakshak.vercel.app", # production frontend URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # or ["*"] to allow all origins (not recommended for prod)
    allow_credentials=True,
    allow_methods=["*"],    # allow all HTTP methods
    allow_headers=["*"],    # allow all headers
)
# # AAPT_PATH = r"C:\Users\manna\AppData\Local\Android\Sdk\build-tools\35.0.0\aapt.exe"
# AAPT_PATH = os.getenv("AAPT_PATH", "/android-sdk/build-tools/35.0.0/aapt")
AAPT_PATH = shutil.which("aapt")

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = AsyncMongoClient(MONGO_URI)
db = client["apkscannerdb"]
scans_collection = db["scan_details"]
signature_collection = db["signatureCollection"]

def serialize_apk_details(details: dict) -> dict:
    """
    Convert ApkFile.as_dict() output into Mongo-safe dict.
    Keep only essential fields, convert Enums and tuples to serializable types.
    """
    allowed_keys = [
        "app_name", "package_name", "version_name", "version_code",
    ]

    def convert(value):
        if isinstance(value, Enum):
            return value.name
        elif isinstance(value, tuple):
            return list(value)
        elif isinstance(value, dict):
            return {str(k): convert(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [convert(v) for v in value]
        else:
            return value

    filtered = {k: details.get(k) for k in allowed_keys if k in details}

    # Ensure app_name is always extracted from labels if missing
    if not filtered.get("app_name") and "labels" in details:
        labels = details.get("labels", {})
        filtered["app_name"] = labels.get("en") or next(iter(labels.values()), None)

    return convert(filtered)

# Example route
@app.get("/")
async def root():
    return {"msg": "API running"}


@app.post("/upload_apk/",summary="Upload APK File",description="Allows to upload only .apk files and returns a scanID")
async def upload_apk(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files allowed")

    scan_id = str(uuid.uuid4())
    tmpdir = tempfile.mkdtemp()
    apk_path = os.path.join(tmpdir, file.filename)

    with open(apk_path, "wb") as f:
        f.write(await file.read())

    doc = {
            "scan_id": scan_id,
            "apk_path": apk_path,
            "status": "uploaded",
            "result": None
        }
    await scans_collection.insert_one(doc)
    return {"scan_id": scan_id, "status": "uploaded"}




@app.post(
    "/scan_metadata/{scan_id}/",
    summary="Scan APK metadata",
    description="Extract APK metadata and compare with Google Play Store"
)
async def scan_metadata(scan_id: str):
    print(f"[INFO] Starting metadata scan for scan_id={scan_id}")

    # --- Fetch scan record ---
    record = await scans_collection.find_one({"scan_id": scan_id})
    # If result already exists in DB, return it directly (skip processing)
    if record and record.get("result") is not None:
        return {
            "scan_id": scan_id,
            "status": "metadata_scanned",
            "result": record["result"]
        }
    if not record:
        print(f"[ERROR] No scan record found for scan_id={scan_id}")
        raise HTTPException(status_code=404, detail="Scan ID not found")

    apk_path = record.get("apk_path")
    if not apk_path or not os.path.exists(apk_path):
        print(f"[ERROR] APK file not found: {apk_path}")
        raise HTTPException(status_code=400, detail="APK file not found on server")

    result = {}
    missing_fields = []
    score = 100
    reasons = []

    app_name = package_name = version_name = None
    details_serializable = {}

    # --- Extract APK metadata ---
    try:
        details = await run_in_threadpool(
            lambda: ApkFile(path=apk_path, aapt_path=AAPT_PATH).as_dict()
        )
        details_serializable = serialize_apk_details(details)

        app_name = details.get("app_name")
        package_name = details.get("package_name")
        version_name = details.get("version_name")

        for key, value in {"package_name": package_name, "version_name": version_name}.items():
            if not value:
                missing_fields.append(key)
                print(f"[WARNING] Missing field: {key}")
                score -= 5
                reasons.append(f"⚠️ Missing field: {key}")

        result["apk_details"] = details_serializable

    except Exception as e:
        print(f"[EXCEPTION] APK parsing failed: {e}")
        result["apk_details_error"] = str(e)
        score -= 50
        reasons.append(f"❌ APK parsing failed: {e}")

    # --- Compare with Google Play Store ---
    play_store_match = {}
    try:
        if package_name:
            try:
                play_details = await asyncio.wait_for(
                    run_in_threadpool(lambda: play_app(package_name, lang="en", country="us")),
                    timeout=15  # timeout in seconds
                )
            except asyncio.TimeoutError:
                print("[ERROR] Play Store lookup timed out")
                play_store_match = {"error": "timeout"}
                score = 0
                reasons.append("❌ Play Store lookup timed out")
                play_details = None

            if play_details:
                # Package name critical
                if package_name == play_details.get("appId"):
                    reasons.append("✅ Package name matches Play Store")
                else:
                    score -= 60
                    reasons.append("❌ Package name mismatch")

                # App name soft check
                if app_name:
                    similarity = SequenceMatcher(
                        None, app_name.lower(), play_details.get("title", "").lower()
                    ).ratio()
                    if similarity > 0.8:
                        reasons.append("✅ App name reasonably similar")
                    elif similarity > 0.5:
                        reasons.append("⚠️ App name partially matches")
                    else:
                        score -= 10
                        reasons.append("❌ App name very different")

                # Version check
                if version_name == play_details.get("version"):
                    reasons.append("✅ Version matches Play Store")
                else:
                    score -= 10
                    reasons.append(
                        f"⚠️ Version mismatch: APK {version_name}, Play Store {play_details.get('version')}"
                    )

                play_store_match = {
                    "app_name_match": app_name.lower() == play_details.get("title", "").lower() if app_name else None,
                    "version_match": version_name == play_details.get("version"),
                    "package_match": package_name == play_details.get("appId"),
                    "developer": play_details.get("developer"),
                    "play_store_title": play_details.get("title"),
                    "play_store_version": play_details.get("version"),
                    "play_store_url": play_details.get("url"),
                }

        else:
            print("[WARNING] Skipping Play Store lookup due to missing package_name")
            play_store_match = "Skipped due to missing package_name"
            score -= 60
            reasons.append("⚠️ Package name missing, skipping Play Store check")

    except Exception as e:
        print(f"[EXCEPTION] Play Store lookup/search failed: {e}")
        play_store_match = {"error": str(e)}
        score -= 90
        reasons.append(f"❌ Play Store lookup failed: {e}")

    # --- Compose final verdict ---
    if score >= 80:
        verdict_text = "Likely Genuine"
    elif 60 <= score < 80:
        verdict_text = "Potentially Modified / Outdated"
    else:
        verdict_text = "Suspicious / Possibly Fake"

    # --- Final structured result ---
    result["play_store_match"] = play_store_match
    result["score"] = score
    result["verdict"] = verdict_text
    if reasons:
        result["reasons"] = reasons
    if missing_fields:
        result["missing_fields"] = missing_fields

    # --- Update MongoDB ---
    try:
        await scans_collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"status": "metadata_scanned", "result": result}}
        )
        print(f"[INFO] Scan {scan_id} completed and saved to MongoDB")
    except Exception as e:
        print(f"[EXCEPTION] MongoDB update failed: {e}")
        raise HTTPException(status_code=500, detail=f"MongoDB update failed: {e}")

    return {"scan_id": scan_id, "status": "metadata_scanned", "result": result}

import os
import re
import subprocess
from fastapi import HTTPException

@app.post(
    "/scan_signature/{scan_id}/",
    summary="Check APK Signature",
    description="Extract APK signing certificate using Androguard CLI and compare with trusted DB signatures"
)
async def scan_signature(scan_id: str):
    print(f"[INFO] Starting signature scan for scan_id={scan_id}")

    # --- Fetch scan record ---
    record = await scans_collection.find_one({"scan_id": scan_id})
    if record and record.get("signature_result") is not None:
        return {
            "scan_id": scan_id,
            "status": "signature_scanned",
            "result": record["signature_result"]
        }
    if not record:
        print(f"[ERROR] No scan record found for scan_id={scan_id}")
        raise HTTPException(status_code=404, detail="Scan ID not found")

    apk_path = record.get("apk_path")
    if not apk_path or not os.path.exists(apk_path):
        print(f"[ERROR] APK file not found: {apk_path}")
        raise HTTPException(status_code=400, detail="APK file not found on server")


    score = 100
    reasons = []
    extracted_sigs = []
    trusted_sigs = []
    sig_match = False

    # --- Run Androguard CLI ---
    try:
        cmd = ["androguard", "sign", apk_path, "--hash", "sha256"]
        print(f"[DEBUG] Running: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        print(f"[DEBUG] Androguard output:\n{output}")

        pkg_pattern = re.search(r"package:\s+'([\w\.]+)'", output)
        package_name = pkg_pattern.group(1) if pkg_pattern else None
        app_name = record.get("app_name") 
        # Regex to find SHA1 or SHA256
        sha_pattern = re.compile(r"sha256\s+([0-9a-fA-F:]+)")
        extracted_sigs = [m.group(1).replace(":", "").upper() for m in sha_pattern.finditer(output)]

        if not extracted_sigs:
            score = 0
            reasons.append("❌ No signature extracted from Androguard CLI")

    except subprocess.TimeoutExpired:
        print("[ERROR] Androguard CLI timed out")
        score = 0
        reasons.append("❌ Androguard CLI timed out")
    except Exception as e:
        print(f"[EXCEPTION] Androguard CLI execution failed: {e}")
        score = 0
        reasons.append(f"❌ Androguard CLI failed: {e}")

    # --- Lookup trusted signatures from DB ---
    try:
        if package_name:
            sig_record = await signature_collection.find_one({"packageName": package_name})
            if sig_record and "signatures" in sig_record:
                trusted_sigs = [s.upper() for s in sig_record["signatures"]]
            else:
                reasons.append("⚠️ No trusted signature found for this package in DB")
                score -= 40
        else:
            reasons.append("⚠️ No package_name available to check signatures")
            score -= 90
    except Exception as e:
        print(f"[EXCEPTION] Signature DB lookup failed: {e}")
        reasons.append(f"❌ Signature DB lookup failed: {e}")
        score = 0

    # --- Compare ---
    if extracted_sigs and trusted_sigs:
        for sig in extracted_sigs:
            if sig in trusted_sigs:
                sig_match = True
                break

        if sig_match:
            reasons.append("✅ APK signature matches trusted certificate")
        else:
            score -= 60
            reasons.append("❌ APK signature does not match trusted certificate")

    # --- Verdict ---
    if score >= 90:
        verdict_text = "Likely Genuine"
    elif 60 <= score < 90:
        verdict_text = "Potentially Modified Needs Review"
    else:
        verdict_text = "Suspicious / Fake"

    result = {
        "app_details": {
            "app_name": app_name,
            "package_name": package_name,
        },
        "extracted_signatures": extracted_sigs,
        "trusted_signatures": trusted_sigs,
        "signature_match": sig_match,
        "score": score,
        "verdict": verdict_text,
        "reasons": reasons
    }

    # --- Update DB ---
    try:
        await scans_collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"status": "signature_scanned", "signature_result": result}}
        )
        print(f"[INFO] Signature scan {scan_id} completed and saved to MongoDB")
    except Exception as e:
        print(f"[EXCEPTION] MongoDB update failed: {e}")
        raise HTTPException(status_code=500, detail=f"MongoDB update failed: {e}")

    return {
        "scan_id": scan_id,
        "status": "signature_scanned",
        "result": result
    }
    
    
# Add near your other imports
import requests
import os

# Get the key from your .env file
# You can get a key from the Google Cloud Console for free
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# -------------------------------------------------------------------
# A NEW HELPER FUNCTION TO CHECK URLs WITH GOOGLE SAFE BROWSING
# -------------------------------------------------------------------
def check_urls_google_safe_browsing(urls_to_check: list[str]) -> list[str]:
    """
    Checks a batch of URLs against the Google Safe Browsing API v4.
    Returns a list of URLs that were flagged as malicious.
    """
    if not GOOGLE_API_KEY:
        print("[WARNING] GOOGLE_API_KEY not configured. Skipping Safe Browsing check.")
        return []

    if not urls_to_check:
        return []
        
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    
    # The API can check up to 500 URLs in a single request
    payload = {
        "client": {"clientId": "apk-scanner", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls_to_check]
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=20)
        response.raise_for_status() # Raise an exception for bad status codes
        
        data = response.json()
        malicious_urls = [match['threat']['url'] for match in data.get('matches', [])]
        return malicious_urls
        
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Google Safe Browsing API request failed: {e}")
        return []

# You would call this from your worker thread like this:
# malicious_urls = check_urls_google_safe_browsing(list(all_urls))

import subprocess
import threading
import asyncio
import re
import yara
import shutil
import tempfile
from datetime import datetime

# Config (tune as needed)
APKTOOL_JAR = os.getenv("APKTOOL_JAR", r"C:\Windows\apktool\apktool.jar")
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "apk_rules.yar")
APKTOOL_TIMEOUT = int(os.getenv("APKTOOL_TIMEOUT", "900"))  # seconds
SCAN_FILE_LIMIT = int(os.getenv("SCAN_FILE_LIMIT", "100000"))
PROGRESS_UPDATE_EVERY = int(os.getenv("PROGRESS_UPDATE_EVERY", "50"))

# Helper used by the worker thread to schedule async DB updates on the main loop
def _push_progress_from_thread(loop: asyncio.AbstractEventLoop, scan_id: str, message: str):
    """
    Schedule an async push to the scans_collection.progress_logs array from a worker thread.
    """
    entry = f"{datetime.utcnow().isoformat()} {message}"
    coro = scans_collection.update_one({"scan_id": scan_id}, {"$push": {"progress_logs": entry}})
    # schedule and don't block; errors will be logged by the event loop if they occur
    asyncio.run_coroutine_threadsafe(coro, loop)

def _set_status_from_thread(loop: asyncio.AbstractEventLoop, scan_id: str, status: str, extra: dict | None = None):
    payload = {"status": status, "updated_at": datetime.utcnow().isoformat()}
    if extra:
        payload.update(extra)
    coro = scans_collection.update_one({"scan_id": scan_id}, {"$set": payload})
    asyncio.run_coroutine_threadsafe(coro, loop)

# Worker thread that runs apktool and then yara+regex scanning
def _worker_deep_scan(loop: asyncio.AbstractEventLoop, scan_id: str, apk_path: str, temp_dir: str):
    try:
        # 1) run apktool (stream stdout -> progress logs)
        if not os.path.exists(APKTOOL_JAR):
            _set_status_from_thread(loop, scan_id, "failed", {"error": f"APKTOOL_JAR missing at {APKTOOL_JAR}"})
            _push_progress_from_thread(loop, scan_id, f"APKTOOL_JAR missing at {APKTOOL_JAR}")
            return

        apktool_cmd = ["java", "-jar", APKTOOL_JAR, "d", "-f", apk_path, "-o", temp_dir]
        _push_progress_from_thread(loop, scan_id, f"Starting apktool: {' '.join(apktool_cmd)}")

        proc = subprocess.Popen(apktool_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        start_time = datetime.utcnow()
        # Stream lines
        for raw_line in iter(proc.stdout.readline, ""):
            line = raw_line.rstrip()
            if line:
                _push_progress_from_thread(loop, scan_id, f"apktool: {line}")

            # cancellation check (non-blocking)
            try:
                future = asyncio.run_coroutine_threadsafe(scans_collection.find_one({"scan_id": scan_id}, {"status": 1}), loop)
                doc = future.result(timeout=1)
            except Exception:
                doc = None

            if doc and doc.get("status") == "cancelled":
                _push_progress_from_thread(loop, scan_id, "Cancellation requested; terminating apktool")
                try:
                    proc.terminate()
                except Exception:
                    pass
                _set_status_from_thread(loop, scan_id, "cancelled")
                return

            # overall apktool timeout guard
            if (datetime.utcnow() - start_time).total_seconds() > APKTOOL_TIMEOUT:
                _push_progress_from_thread(loop, scan_id, f"apktool timeout ({APKTOOL_TIMEOUT}s) reached; killing")
                try:
                    proc.terminate()
                except Exception:
                    pass
                _set_status_from_thread(loop, scan_id, "failed", {"error": "apktool_timeout"})
                return

        # ensure process ended
        proc.wait()
        if proc.returncode != 0:
            _push_progress_from_thread(loop, scan_id, f"apktool exited with code {proc.returncode}")
            _set_status_from_thread(loop, scan_id, "failed", {"error": f"apktool_exit_{proc.returncode}"})
            return

        _push_progress_from_thread(loop, scan_id, f"apktool finished, decompiled to {temp_dir}")
        _set_status_from_thread(loop, scan_id, "decompiled")

        # 2) compile YARA rules
        try:
            yara_rules = yara.compile(filepath=YARA_RULES_PATH)
            _push_progress_from_thread(loop, scan_id, "YARA rules compiled")
        except Exception as e:
            _push_progress_from_thread(loop, scan_id, f"YARA compile error: {e}")
            _set_status_from_thread(loop, scan_id, "failed", {"error": f"yara_compile_error: {e}"})
            return

        # 3) scan files (regex + yara)
        url_rx = re.compile(r'https?://[^\s"\'<>]+')
        perm_rx = re.compile(r'android\.permission\.[A-Z_0-9]+')
        dangerous_reasons = {
            "android.permission.SEND_SMS": "Allows sending SMS (fraud/cost)",
            "android.permission.READ_SMS": "Reads SMS (OTP leakage)",
            "android.permission.WRITE_EXTERNAL_STORAGE": "Legacy write to shared storage",
        }

        all_urls = set()
        all_perms = set()
        suspicious_findings = []
        files_scanned = 0
        total_files = 0
        for _, _, files in os.walk(temp_dir):
            total_files += len(files)
        _push_progress_from_thread(loop, scan_id, f"Starting file scan ({total_files} files)")

        for root, _, files in os.walk(temp_dir):
            # quick cancel check
            try:
                future = asyncio.run_coroutine_threadsafe(scans_collection.find_one({"scan_id": scan_id}, {"status": 1}), loop)
                doc = future.result(timeout=1)
            except Exception:
                doc = None
            if doc and doc.get("status") == "cancelled":
                _push_progress_from_thread(loop, scan_id, "Scan cancelled during file walk")
                _set_status_from_thread(loop, scan_id, "cancelled")
                return

            for fname in files:
                files_scanned += 1
                if files_scanned > SCAN_FILE_LIMIT:
                    _push_progress_from_thread(loop, scan_id, f"File limit exceeded ({SCAN_FILE_LIMIT}); aborting")
                    _set_status_from_thread(loop, scan_id, "failed", {"error": "file_limit_exceeded"})
                    return

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as fh:
                        content = fh.read()
                except Exception as e:
                    _push_progress_from_thread(loop, scan_id, f"Warning: cannot open {os.path.relpath(fpath, temp_dir)}: {e}")
                    continue

                # regex
                try:
                    text = content.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""

                for m in url_rx.finditer(text):
                    all_urls.add(m.group(0))
                for m in perm_rx.finditer(text):
                    all_perms.add(m.group(0))

                # yara matches
                try:
                    matches = yara_rules.match(data=content)
                except Exception as e:
                    _push_progress_from_thread(loop, scan_id, f"YARA error on {os.path.relpath(fpath,temp_dir)}: {e}")
                    matches = []

                if matches:
                    _push_progress_from_thread(loop, scan_id, f"YARA matched {len(matches)} rule(s) in {os.path.relpath(fpath, temp_dir)}")

                for match in matches:
                    for s in match.strings:
                        for inst in s.instances:
                            try:
                                offset = inst.offset
                                matched_bytes = inst.matched_data
                                identifier = s.identifier

                                try:
                                    matched_text = matched_bytes.decode("utf-8", "ignore")
                                except Exception:
                                    matched_text = str(matched_bytes)

                                finding = {
                                    "file_path": os.path.relpath(fpath, temp_dir),
                                    "line_number": content[:offset].count(b'\n') + 1,
                                    "rule_name": match.rule,
                                    "severity": match.meta.get("severity", "unknown"),
                                    "matched_data": matched_text,
                                    "string_id": identifier
                                }

                                if match.rule == "Suspicious_Permissions":
                                    finding["reasoning"] = dangerous_reasons.get(
                                        matched_text, "Potentially dangerous permission"
                                    )

                                suspicious_findings.append(finding)

                            except Exception as e:
                                _push_progress_from_thread(
                                    loop,
                                    scan_id,
                                    f"Error parsing YARA match in {fpath}: {e}"
                                )

                if files_scanned % PROGRESS_UPDATE_EVERY == 0:
                    _push_progress_from_thread(loop, scan_id, f"Scanned {files_scanned}/{total_files} files")

        # 4) build final report and save
        _push_progress_from_thread(loop, scan_id, f"Checking {len(all_urls)} URLs with Google Safe Browsing...")
        flagged_urls = check_urls_google_safe_browsing(list(all_urls))
        _push_progress_from_thread(loop, scan_id, f"Google Safe Browsing check complete. Found {len(flagged_urls)} suspicious URLs.")

        # Log each flagged URL for clarity in the progress logs
        if flagged_urls:
            for url in flagged_urls:
                _push_progress_from_thread(loop, scan_id, f"⚠️ Suspicious URL flagged by Google: {url}")

        # 5) Build final report and save
        report = {
            "scan_summary": {"apk_path": apk_path, "total_files_scanned": files_scanned, "scan_timestamp": datetime.utcnow().isoformat()},
            "inventory": {"all_urls_found": sorted(list(all_urls)), "all_permissions_found": sorted(list(all_perms))},
            "suspicious_findings": suspicious_findings,
            "safe_browsing_results": {"flagged_urls": flagged_urls}
        }

        asyncio.run_coroutine_threadsafe(
            scans_collection.update_one({"scan_id": scan_id}, {"$set": {"status": "deep_scanned", "deep_scan_result": report}}),
            loop
        )
        _push_progress_from_thread(loop, scan_id, f"Deep scan complete. Files scanned: {files_scanned}")

    except Exception as ex:
        _push_progress_from_thread(loop, scan_id, f"Worker exception: {ex}")
        _set_status_from_thread(loop, scan_id, "failed", {"error": str(ex)})
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            _push_progress_from_thread(loop, scan_id, f"Cleaned temp dir {temp_dir}")
        except Exception: 
            pass
            

@app.post("/deep_scan/{scan_id}/", summary="Deep APK scan", description="Start decompile + YARA in background (non-blocking)")
async def deep_scan(scan_id: str):
    record = await scans_collection.find_one({"scan_id": scan_id})
    # If deep_scan_result already exists, return status only (don't start new scan)
    if record and record.get("deep_scan_result") is not None:
        return {"scan_id": scan_id, "status": record.get("status")}
    if not record:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    apk_path = record.get("apk_path")
    if not apk_path or not os.path.exists(apk_path):
        raise HTTPException(status_code=400, detail="APK file not found on server")

    # create temp dir for decompile (worker will use and remove it)
    temp_dir = tempfile.mkdtemp(prefix=f"deep_scan_{scan_id}_")

    # reset progress logs and mark queued
    await scans_collection.update_one(
        {"scan_id": scan_id},
        {"$set": {"status": "queued", "progress_logs": [], "deep_scan_result": None, "temp_dir": temp_dir}}
    )

    # start the worker thread (pass the current asyncio loop)
    loop = asyncio.get_running_loop()
    thread = threading.Thread(target=_worker_deep_scan, args=(loop, scan_id, apk_path, temp_dir), daemon=True)
    thread.start()

    return {"scan_id": scan_id, "status": "started"}

@app.get("/scan_status/{scan_id}/", summary="Check scan progress", description="Returns live status and progress updates for a scan")
async def scan_status(scan_id: str):
    record = await scans_collection.find_one({"scan_id": scan_id}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return record

@app.post("/scan/{scan_id}/cancel", summary="Cancel a running scan", description="Mark scan cancelled; worker checks DB and stops")
async def cancel_scan(scan_id: str):
    await scans_collection.update_one({"scan_id": scan_id}, {"$set": {"status": "cancelled"}})
    return {"scan_id": scan_id, "status": "cancelling"}

from collections import Counter
def _compute_deep_verdict(deep_scan_result: dict) -> dict:
    """
    Improved rule-based classifier for APK scans.
    Now context-aware: separates sloppy configs from true malicious risk.  
    Prepares for future integration with external threat intelligence APIs.
    """
    findings = deep_scan_result.get("suspicious_findings", []) or []
    inventory = deep_scan_result.get("inventory", {}) or {}
    all_urls = inventory.get("all_urls_found", []) or []
    all_perms = set(inventory.get("all_permissions_found", []) or [])

    # Deduplicate findings by (rule, matched_data)
    unique_findings = {}
    for f in findings:
        key = (f.get("rule_name"), (f.get("matched_data") or "").strip())
        if key not in unique_findings:
            unique_findings[key] = f
    unique_findings = list(unique_findings.values())

    # Weight adjustments
    severity_weights = {
        "critical": 90,
        "high": 35,   # lowered slightly
        "medium": 12,
        "unknown": 5,
    }

    total_deduction = 0
    reasons = []
    severity_counts = Counter()
    rule_counts = Counter()

    for f in unique_findings:
        rule = f.get("rule_name", "unknown")
        matched = (f.get("matched_data") or "").strip()
        sev = (f.get("severity") or "unknown").lower()

        rule_counts[rule] += 1
        severity_counts[sev] += 1

        ded = severity_weights.get(sev, severity_weights["unknown"])

        if rule == "High_Confidence_Secrets" or sev == "critical":
            ded = severity_weights["critical"]
            reasons.append(f"Critical secret/API key found: {matched}")
        elif rule == "Suspicious_Permissions":
            if "RECORD_AUDIO" in matched or "SEND_SMS" in matched or "READ_CONTACTS" in matched:
                ded += 15  # escalate sensitive ones
                reasons.append(f"Sensitive permission: {matched}")
            elif "LOCATION" in matched:
                ded += 8   # location less severe
                reasons.append(f"Location access permission: {matched}")
            else:
                reasons.append(f"Suspicious permission: {matched}")
        elif rule == "Manifest_Security_Risks":
            if "debuggable" in matched.lower():
                ded = 15
                reasons.append("Debuggable build (unsafe, but not malware).")
            elif "allowbackup" in matched.lower():
                ded = 10
                reasons.append("Backup enabled (data could be exposed).")
            elif "exported" in matched.lower():
                ded = 12
                reasons.append("Component exported (review required).")
        elif rule == "Suspicious_Network_Endpoints":
            if ".onion" in matched or "ngrok" in matched or "serveo" in matched:
                ded += 25
                reasons.append(f"Potential tunneling endpoint: {matched}")
            else:
                ded += 5
                reasons.append(f"Unusual domain indicator: {matched}")
        else:
            reasons.append(f"{rule}: {matched}")

        total_deduction += ded

    # Extra inventory checks
    risky_perms = {
        "android.permission.RECORD_AUDIO",
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.CAMERA",
        "android.permission.READ_CALL_LOG"
    }
    for p in sorted(all_perms.intersection(risky_perms)):
        reasons.append(f"Declared risky permission: {p}")
        total_deduction += 12

    # URL count heuristic
    if len(all_urls) > 20:
        reasons.append(f"High number of URLs found: {len(all_urls)}")
        total_deduction += 15

    # Cap deductions
    total_deduction = min(total_deduction, 95)
    score = max(0, 100 - total_deduction)

    # New verdict mapping
    if score <= 30:
        verdict = "High Risk / Likely Malicious"
    elif score <= 55:
        verdict = "Suspicious / Potentially Risky"
    elif score <= 75:
        verdict = "Needs Review (gray zone)"
    elif score <= 90:
        verdict = "Likely Safe, but has security issues"
    else:
        verdict = "Safe / Clean"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "severity_counts": dict(severity_counts),
        "rule_counts": dict(rule_counts),
        "url_count": len(all_urls),
        "inventory_risky_permissions": list(all_perms.intersection(risky_perms)),
        "top_findings": unique_findings[:10]
    }


@app.get("/deep_result/{scan_id}/", summary="Get deep-scan result + verdict", description="Returns the deep_scan_result and a rule-based verdict derived from YARA findings + inventory")
async def get_deep_result(scan_id: str):
    # fetch record
    record = await scans_collection.find_one({"scan_id": scan_id}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    deep = record.get("deep_scan_result")
    if not deep:
        return JSONResponse(
            status_code=200,
            content={
                "scan_id": scan_id,
                "status": record.get("status"),
                "message": "Deep scan not available yet. Use /scan_status/{scan_id}/ to poll progress."
            }
        )

    verdict = _compute_deep_verdict(deep)

    # persist verdict to DB for later retrieval
    try:
        await scans_collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"deep_scan_verdict": verdict, "updated_at": datetime.utcnow().isoformat()}}
        )
    except Exception as e:
        # don't fail the response if DB write fails; just log via response
        verdict["_db_update_error"] = str(e)

    return {"scan_id": scan_id, "status": record.get("status"), "deep_scan_result": deep, "deep_scan_verdict": verdict}

@app.delete("/delete_apk/{scan_id}/", summary="Delete APK by Scan ID", description="Deletes the APK file from server and removes its record from DB")
async def delete_apk(scan_id: str):
    # Fetch scan record
    record = await scans_collection.find_one({"scan_id": scan_id})
    if not record:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    apk_path = record.get("apk_path")

    # Delete the APK file from disk if it exists
    if apk_path and os.path.exists(apk_path):
        try:
            os.remove(apk_path)
            # Also cleanup parent tmpdir if empty
            parent_dir = os.path.dirname(apk_path)
            try:
                os.rmdir(parent_dir)  # removes only if empty
            except OSError:
                pass
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete APK file: {e}")

    # Delete record from MongoDB
        await scans_collection.update_one(
                {"scan_id": scan_id},
                {"$set": {"apk_path": None, "status": "apk_deleted"}}
            )
    return {"scan_id": scan_id, "status": "deleted"}

@app.post("/patch_with_frida/{scan_id}/")
async def patch_with_frida(scan_id: str):
    print(f"[INFO] Starting Frida patch for scan_id={scan_id}")

    record = await scans_collection.find_one({"scan_id": scan_id})
    if not record: 
        print(f"[ERROR] No scan record found for {scan_id}")
        raise HTTPException(status_code=404, detail="Scan ID not found")

    apk_path = record["apk_path"]
    if not apk_path or not os.path.exists(apk_path):
        print(f"[ERROR] APK not found on disk: {apk_path}")
        raise HTTPException(status_code=400, detail="APK not found")

    tmpdir = tempfile.mkdtemp(prefix=f"frida_patch_{scan_id}_")
    decoded = os.path.join(tmpdir, "decoded")
    patched = os.path.join(tmpdir, "patched.apk")
    print(f"[INFO] Working directory: {tmpdir}")

    # 1) decode
    print(f"[STEP] Running apktool decode on {apk_path}")
    apktool_cmd = ["java", "-jar", APKTOOL_JAR, "d", "-f", apk_path, "-o", decoded]
    subprocess.run(apktool_cmd, check=True)

    # 2) inject gadget
    arch = "x86"  # Genycloud free = x86 image
    libdir = os.path.join(decoded, "lib", arch)
    os.makedirs(libdir, exist_ok=True)

    gadget_src = os.getenv("FRIDA_GADGET_PATH", "/app/frida-gadget.so")
    if not os.path.exists(gadget_src):
        print(f"[ERROR] Frida gadget not found at {gadget_src}")
        raise HTTPException(status_code=500, detail=f"Frida gadget not found at {gadget_src}")

    print(f"[STEP] Copying gadget from {gadget_src} -> {libdir}")
    shutil.copy(gadget_src, os.path.join(libdir, "libfrida-gadget.so"))

    # 3) add config
    print(f"[STEP] Creating frida-gadget.config in assets/")
    assets = os.path.join(decoded, "assets")
    os.makedirs(assets, exist_ok=True)
    config_path = os.path.join(assets, "frida-gadget.config")
    with open(config_path, "w") as f:
        f.write(json.dumps({
            "interaction": {"type": "listen", "address": "0.0.0.0", "port": 27042}
        }))
    print(f"[INFO] Wrote frida-gadget.config at {config_path}")

    # 4) rebuild
    print("[STEP] Rebuilding APK with apktool")
    subprocess.run(["java", "-jar", APKTOOL_JAR, "b", decoded, "-o", patched], check=True)
    print(f"[INFO] Rebuilt APK at {patched}")

    # 5) sign
    signed = patched.replace(".apk", "_signed.apk")
    keystore = os.getenv("DEBUG_KEYSTORE", "/app/debug.keystore")
    print(f"[STEP] Signing APK with keystore={keystore}")
    subprocess.run([
        "apksigner", "sign",
        "--ks", keystore,
        "--ks-pass", "pass:android",
        "--out", signed, patched
    ], check=True)
    print(f"[INFO] Signed APK saved at {signed}")

    await scans_collection.update_one(
        {"scan_id": scan_id},
        {"$set": {
            "patched_apk_path": signed,
            "status": "frida_patched",
            "updated_at": datetime.utcnow().isoformat()
        }}
    )
    print(f"[SUCCESS] Patched APK ready for scan_id={scan_id}")

    return {"scan_id": scan_id, "status": "frida_patched", "patched_apk": signed}

from fastapi.responses import FileResponse

@app.get("/download_patched/{scan_id}/", summary="Download patched APK")
async def download_patched_apk(scan_id: str):
    # 1️⃣ Find scan record
    record = await scans_collection.find_one({"scan_id": scan_id})
    if not record:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    patched_apk_path = record.get("patched_apk_path")
    if not patched_apk_path or not os.path.exists(patched_apk_path):
        raise HTTPException(status_code=400, detail="Patched APK not found. Run /patch_with_frida first.")

    # 2️⃣ Return the file
    filename = f"{record.get('package_name', 'app')}_patched.apk"
    return FileResponse(
        path=patched_apk_path,
        filename=filename,
        media_type="application/vnd.android.package-archive"
    )


import aiohttp

APPETIZE_API_KEY = os.getenv("APPETIZE_API_KEY")
APPETIZE_API_URL = "https://api.appetize.io/v1/apps"

@app.post("/dynamic_run/{scan_id}/", summary="Upload APK to Appetize", description="Uploads a previously uploaded APK directly to Appetize and returns publicKey")
async def dynamic_run(scan_id: str):
    scan_doc = await scans_collection.find_one({"scan_id": scan_id})
    # If appetize_publicKey already exists, return it directly (skip upload)
    if scan_doc and scan_doc.get("appetize_publicKey"):
        return {
            "scan_id": scan_id,
            "publicKey": scan_doc.get("appetize_publicKey"),
            "status": "uploaded_to_appetize"
        }
    if not scan_doc:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    apk_path = scan_doc.get("apk_path")
    if not apk_path or not os.path.exists(apk_path):
        raise HTTPException(status_code=400, detail="APK file not found on server")

    form_data = aiohttp.FormData()
    form_data.add_field("file", open(apk_path, "rb"), filename=os.path.basename(apk_path))
    form_data.add_field("platform", "android")
    form_data.add_field("appPermissions.run", "public")
    form_data.add_field("appPermissions.networkProxy", "public")
    form_data.add_field("appPermissions.networkIntercept", "public")
    form_data.add_field("appPermissions.debugLog", "public")
    form_data.add_field("appPermissions.adbConnect", "public")
    form_data.add_field("appPermissions.androidPackageManager", "public")

    async with aiohttp.ClientSession() as session:
        async with session.post(
            APPETIZE_API_URL,
            headers={"X-API-KEY": APPETIZE_API_KEY},
            data=form_data
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise HTTPException(status_code=resp.status, detail=f"Appetize API error: {text}")
            data = await resp.json()

    await scans_collection.update_one(
        {"scan_id": scan_id},
        {"$set": {"appetize_publicKey": data.get("publicKey"), "status": "uploaded_to_appetize"}}
    )

    return {"scan_id": scan_id, "publicKey": data.get("publicKey"), "status": "uploaded_to_appetize"}
