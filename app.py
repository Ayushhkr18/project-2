import os
import json
import time
import asyncio
from typing import List, Dict
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import honeypot_ssh
import simulator
from generator import GenerativeContentEngine
from world_builder import VirtualFilesystemBuilder

app = FastAPI(title="AI-Powered Cyber Deception Platform")

# Global Session & Event Logs Cache
active_sessions: Dict[str, dict] = {}
all_events: List[dict] = []
event_queue = asyncio.Queue()

# Setup honeypot callback adapters
def on_session_start(session_id, ip, username):
    session_data = {
        "session_id": session_id,
        "ip": ip,
        "username": username,
        "status": "active",
        "start_time": time_str(),
        "commands": []
    }
    active_sessions[session_id] = session_data
    
    # Broadcast start event
    asyncio.run_coroutine_threadsafe(
        event_queue.put({
            "type": "session_start",
            "session": session_data
        }),
        loop
    )

def on_session_event(session_id, event):
    event["timestamp"] = time_str()
    all_events.append(event)
    
    if session_id in active_sessions:
        active_sessions[session_id]["commands"].append(event)
        
    asyncio.run_coroutine_threadsafe(
        event_queue.put({
            "type": "session_event",
            "session_id": session_id,
            "event": event
        }),
        loop
    )

def on_session_end(session_id):
    if session_id in active_sessions:
        active_sessions[session_id]["status"] = "disconnected"
        
    asyncio.run_coroutine_threadsafe(
        event_queue.put({
            "type": "session_end",
            "session_id": session_id
        }),
        loop
    )

# Connect SSH honeypot callbacks
honeypot_ssh.ON_SESSION_START = on_session_start
honeypot_ssh.ON_SESSION_EVENT = on_session_event
honeypot_ssh.ON_SESSION_END = on_session_end

def time_str():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Start SSH listener in the background
ssh_socket = None

@app.on_event("startup")
async def startup_event():
    global loop, ssh_socket
    loop = asyncio.get_event_loop()
    ssh_socket = honeypot_ssh.start_ssh_honeypot(port=2222)

@app.on_event("shutdown")
async def shutdown_event():
    if ssh_socket:
        ssh_socket.close()

# API Endpoints
@app.get("/api/sessions")
def get_sessions():
    return list(active_sessions.values())

@app.get("/api/events")
def get_events():
    return all_events

@app.get("/api/honeytokens")
def get_honeytokens():
    # Return a generated set of tokens for view
    gen = GenerativeContentEngine(seed=42)
    builder = VirtualFilesystemBuilder(gen)
    return builder.honeytokens

@app.get("/api/filesystem")
def get_filesystem():
    gen = GenerativeContentEngine(seed=42)
    builder = VirtualFilesystemBuilder(gen)
    return builder.get_fs_tree()

@app.post("/api/simulator/trigger")
def trigger_simulator():
    simulator.trigger_bg_simulation()
    return {"status": "triggered"}

@app.post("/api/honeypot/restart")
def restart_honeypot():
    global ssh_socket
    if ssh_socket:
        ssh_socket.close()
    ssh_socket = honeypot_ssh.start_ssh_honeypot(port=2222)
    return {"status": "restarted"}

# Server-Sent Events (SSE) stream for live updates
@app.get("/api/stream")
async def events_stream(request: Request):
    async def event_generator():
        while True:
            # Check client connection state
            if await request.is_disconnected():
                break
            
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                yield f"data: {json.dumps(event)}\n\n"
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Serve frontend assets static mapping
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
else:
    # Fallback default route if directories are loaded flat
    scratch_frontend = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
    app.mount("/", StaticFiles(directory=scratch_frontend, html=True), name="frontend")
