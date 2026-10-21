"""Arcus platform WebSocket client."""

import asyncio
import json
import os
import uuid
from pathlib import Path

import requests
import websockets

CONFIG_DIR = Path.home() / ".oculus"
SESSION_FILE = CONFIG_DIR / "session.json"


def load_session():
   if SESSION_FILE.exists():
      with open(SESSION_FILE) as f:
         return json.load(f)
   return None


def save_session(data):
   CONFIG_DIR.mkdir(parents=True, exist_ok=True)
   with open(SESSION_FILE, "w") as f:
      json.dump(data, f, indent=2)
   os.chmod(SESSION_FILE, 0o600)


def clear_session():
   if SESSION_FILE.exists():
      SESSION_FILE.unlink()


class ArcusClient:
   def __init__(self, host, session_token=None, place_id=None):
      self.host = host.rstrip("/")
      if not self.host.startswith("http"):
         self.host = "https://" + self.host
      self.session_token = session_token
      self.place_id = place_id
      self.ws = None
      self._session_info = None

   def login(self, username, password):
      resp = requests.post(f"{self.host}/login",
                           data={"user": username, "password": password},
                           allow_redirects=False, verify=True)
      for name in ("irisAuthToken", "prodIrisAuthToken", "devIrisAuthToken"):
         token = resp.cookies.get(name)
         if token:
            self.session_token = token
            return token
      raise RuntimeError(f"Login failed (HTTP {resp.status_code})")

   def logout(self):
      if self.session_token:
         try:
            requests.post(f"{self.host}/logout",
                          cookies={"irisAuthToken": self.session_token}, verify=True)
         except Exception:
            pass
      self.session_token = None
      clear_session()

   async def connect(self):
      ws_url = self.host.replace("https://", "wss://").replace("http://", "ws://")
      self.ws = await websockets.connect(
         ws_url + "/websocket",
         additional_headers={"Authorization": self.session_token},
         max_size=1024 * 1024,
      )
      raw = await self.ws.recv()
      msg = json.loads(raw)
      if msg.get("type") == "sess:SessionCreated":
         self._session_info = msg.get("payload", {}).get("attributes", {})
      return msg

   async def disconnect(self):
      if self.ws:
         await self.ws.close()
         self.ws = None

   async def ensure_connected(self):
      if not self.ws:
         await self.connect()
         if self.place_id:
            await self.request("SERV:sess:", "sess:SetActivePlace",
                               {"placeId": self.place_id})

   async def request(self, destination, command, attributes=None, timeout=30):
      await self.ensure_connected()
      cor_id = str(uuid.uuid4())
      msg = {
         "type": command,
         "headers": {
            "destination": destination,
            "correlationId": cor_id,
            "isRequest": True,
         },
         "payload": {
            "messageType": command,
            "attributes": attributes or {},
         },
      }
      await self.ws.send(json.dumps(msg))

      deadline = asyncio.get_event_loop().time() + timeout
      while True:
         remaining = deadline - asyncio.get_event_loop().time()
         if remaining <= 0:
            raise TimeoutError("Request timed out")
         try:
            raw = await asyncio.wait_for(self.ws.recv(), timeout=remaining)
         except asyncio.TimeoutError:
            raise TimeoutError("Request timed out")
         resp = json.loads(raw)
         if resp.get("headers", {}).get("correlationId") == cor_id:
            payload = resp.get("payload", {})
            if payload.get("messageType") == "Error":
               code = payload.get("attributes", {}).get("code", "?")
               message = payload.get("attributes", {}).get("message", "")
               raise RuntimeError(f"[{code}] {message}")
            return payload.get("attributes", {})

   async def list_devices(self):
      resp = await self.request(f"SERV:place:{self.place_id}", "place:ListDevices")
      return resp.get("devices", [])

   async def get_attributes(self, addr):
      return await self.request(addr, "base:GetAttributes")

   async def set_attributes(self, addr, attrs):
      return await self.request(addr, "base:SetAttributes", attrs)

   async def send_command(self, addr, command, attrs=None):
      return await self.request(addr, command, attrs or {})

   async def list_scenes(self):
      resp = await self.request("SERV:scene:", "scene:ListScenes",
                                {"placeId": self.place_id})
      return resp.get("scenes", [])

   async def list_rules(self):
      resp = await self.request("SERV:rule:", "rule:ListRules",
                                {"placeId": self.place_id})
      return resp.get("rules", [])

   async def list_subsystems(self):
      resp = await self.request(f"SERV:subs:{self.place_id}", "subs:ListSubsystems")
      return resp.get("subsystems", [])

   async def list_people(self):
      resp = await self.request(f"SERV:place:{self.place_id}", "place:ListPersons")
      return resp.get("persons", [])

   async def get_hub(self):
      return await self.request(f"SERV:place:{self.place_id}", "place:GetHub")

   def get_places(self):
      return self._session_info.get("places", []) if self._session_info else []

   async def listen(self, callback):
      await self.ensure_connected()
      while True:
         raw = await self.ws.recv()
         callback(json.loads(raw))
