"""Interactive REPL for the Arcus platform."""

import asyncio
import cmd
import getpass
import json
import readline
import shlex

from .client import ArcusClient, save_session

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
RESET = "\033[0m"


def ppjson(obj):
   print(json.dumps(obj, indent=2, default=str))


def state_color(state):
   s = str(state).upper()
   if s in ("ONLINE", "CONNECTED"):
      return GREEN
   if s in ("OFFLINE", "DISCONNECTED"):
      return RED
   return YELLOW


def parse_kv(args):
   result = {}
   for arg in args:
      if "=" not in arg:
         raise ValueError(f"Expected key=value, got: {arg}")
      key, value = arg.split("=", 1)
      try:
         value = json.loads(value)
      except (json.JSONDecodeError, ValueError):
         pass
      result[key] = value
   return result


class DeviceIndex:
   """Indexes devices for lookup by name fragment or short UUID."""

   def __init__(self, devices, registry):
      self.devices = sorted(devices, key=lambda d: d.get("dev:name", ""))
      self.registry = registry

   def resolve(self, query):
      """Returns (address, device_attrs) or raises ValueError."""
      q = query.lower()
      # exact address
      for d in self.devices:
         if d.get("base:address", "") == query:
            return d["base:address"], d
      # exact name (case insensitive)
      for d in self.devices:
         if d.get("dev:name", "").lower() == q:
            return d["base:address"], d
      # partial match on name or short UUID
      matches = []
      for d in self.devices:
         addr = d.get("base:address", "")
         name = d.get("dev:name", "")
         short_id = addr.split(":")[-1][:8] if ":" in addr else ""
         if q in name.lower() or q in short_id.lower():
            matches.append(d)
      if len(matches) == 1:
         return matches[0]["base:address"], matches[0]
      if len(matches) > 1:
         lines = [f"{YELLOW}Ambiguous — {len(matches)} matches:{RESET}"]
         for d in matches:
            name = d.get("dev:name", "?")
            short = d.get("base:address", "").split(":")[-1][:8]
            lines.append(f"  {name} ({short})")
         raise ValueError("\n".join(lines))
      raise ValueError(f"No device matching '{query}'")

   def names(self):
      return [d.get("dev:name", "") for d in self.devices if d.get("dev:name")]

   def caps_for(self, addr):
      for d in self.devices:
         if d.get("base:address") == addr:
            return self.registry.namespaces_for_device(d)
      return None


class OculusShell(cmd.Cmd):
   prompt = f"{CYAN}arcus>{RESET} "

   def __init__(self, client, registry):
      super().__init__()
      self.client = client
      self.registry = registry
      self.device_index = None
      self._loop = asyncio.new_event_loop()

   def _run(self, coro):
      return self._loop.run_until_complete(coro)

   def preloop(self):
      if "libedit" in (readline.__doc__ or ""):
         readline.parse_and_bind("bind ^I rl_complete")
      else:
         readline.parse_and_bind("tab: complete")
      readline.set_completer_delims(" \t\n")

      self._run(self.client.ensure_connected())
      self._load_devices()
      n = len(self.device_index.devices) if self.device_index else 0
      ncaps = len(self.registry.capabilities)
      print(f"{DIM}{n} devices, {ncaps} capabilities loaded{RESET}")

   def _load_devices(self):
      try:
         devs = self._run(self.client.list_devices())
         self.device_index = DeviceIndex(devs, self.registry)
      except Exception as e:
         print(f"{RED}Failed to load devices: {e}{RESET}")
         self.device_index = DeviceIndex([], self.registry)

   def _resolve(self, name):
      try:
         return self.device_index.resolve(name)
      except ValueError as e:
         print(str(e))
         return None, None

   def _resolve_silent(self, name):
      try:
         return self.device_index.resolve(name)
      except ValueError:
         return None, None

   def _parse_line(self, line):
      try:
         return shlex.split(line)
      except ValueError:
         return line.split()

   # -- Suppress empty-tab noise --

   def completenames(self, text, *ignored):
      if not text:
         return []
      return super().completenames(text, *ignored)

   def completedefault(self, *ignored):
      return []

   # -- Commands --

   def do_login(self, arg):
      """login [host] — Log in (re-authenticate)"""
      parts = self._parse_line(arg)
      host = parts[0] if parts else input("Host: ")
      user = input("Username: ")
      password = getpass.getpass("Password: ")
      try:
         self.client = ArcusClient(host)
         token = self.client.login(user, password)
         msg = self._run(self.client.connect())
         info = msg.get("payload", {}).get("attributes", {})
         places = info.get("places", [])
         place_id = None
         if places:
            if len(places) == 1:
               place_id = places[0].get("placeId")
            else:
               for i, p in enumerate(places, 1):
                  print(f"  {i}) {p.get('placeName', '?')}")
               choice = input("Place [1]: ").strip() or "1"
               place_id = places[int(choice) - 1].get("placeId")
         if place_id:
            self._run(self.client.request("SERV:sess:", "sess:SetActivePlace",
                                          {"placeId": place_id}))
            self.client.place_id = place_id
         save_session({"host": host, "token": token, "user": user,
                        "place_id": place_id})
         print(f"{GREEN}Logged in as {user}{RESET}")
         self._load_devices()
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_devices(self, arg):
      """List devices"""
      self._load_devices()
      if not self.device_index.devices:
         print("No devices.")
         return
      for d in self.device_index.devices:
         name = d.get("dev:name", "?")
         short_id = d.get("base:address", "").split(":")[-1][:8]
         state = d.get("devconn:state", "")
         driver = d.get("devadv:driverName", "")
         print(f"  {state_color(state)}{name}{RESET}"
               f"  {DIM}{short_id}  {driver}{RESET}")

   def do_device(self, arg):
      """device <name> — Show all attributes for a device"""
      parts = self._parse_line(arg)
      if not parts:
         print("Usage: device <name>")
         return
      addr, _ = self._resolve(parts[0])
      if not addr:
         return
      try:
         attrs = self._run(self.client.get_attributes(addr))
         name = attrs.get("dev:name", addr)
         print(f"\n{BOLD}{name}{RESET}")
         groups = {}
         for key in sorted(attrs.keys()):
            ns = key.split(":")[0] if ":" in key else ""
            groups.setdefault(ns, []).append((key, attrs[key]))
         for ns in sorted(groups.keys()):
            for key, val in groups[ns]:
               rw = ""
               if ":" in key:
                  ns_part, attr_name = key.split(":", 1)
                  cap = self.registry.capabilities.get(ns_part)
                  if cap and attr_name in cap.attributes:
                     a = cap.attributes[attr_name]
                     if "w" in a.readwrite:
                        rw = f" {DIM}(rw){RESET}"
               print(f"  {DIM}{key:<35}{RESET} {val}{rw}")
         print()
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def complete_device(self, text, line, begidx, endidx):
      if not text:
         return []
      return [n for n in self.device_index.names()
              if n.lower().startswith(text.lower())]

   def do_set(self, arg):
      """set <device> <attr>=<value> ... — Set device attributes"""
      parts = self._parse_line(arg)
      if len(parts) < 2:
         print("Usage: set <device> <attr>=<value> ...")
         return
      addr, _ = self._resolve(parts[0])
      if not addr:
         return
      try:
         attrs = parse_kv(parts[1:])
         self._run(self.client.set_attributes(addr, attrs))
         print(f"{GREEN}OK{RESET}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def complete_set(self, text, line, begidx, endidx):
      parts = line[:begidx].split()
      if len(parts) <= 1:
         if not text:
            return []
         return [n for n in self.device_index.names()
                 if n.lower().startswith(text.lower())]
      if len(parts) >= 2 and text:
         dev_name = parts[1]
         addr, _ = self._resolve_silent(dev_name)
         ns_filter = self.device_index.caps_for(addr) if addr else None
         candidates = self.registry.rw_attributes(ns_filter)
         prefix = text.split("=")[0] if "=" in text else text
         return [c + "=" for c in candidates if c.lower().startswith(prefix.lower())]
      return []

   def do_cmd(self, arg):
      """cmd <device> <ns:Method> [param=value ...] — Send a command"""
      parts = self._parse_line(arg)
      if len(parts) < 2:
         print("Usage: cmd <device> <ns:Method> [param=value ...]")
         return
      addr, _ = self._resolve(parts[0])
      if not addr:
         return
      try:
         attrs = parse_kv(parts[2:]) if len(parts) > 2 else {}
         result = self._run(self.client.send_command(addr, parts[1], attrs))
         if result:
            ppjson(result)
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def complete_cmd(self, text, line, begidx, endidx):
      parts = line[:begidx].split()
      if len(parts) <= 1:
         if not text:
            return []
         return [n for n in self.device_index.names()
                 if n.lower().startswith(text.lower())]
      if len(parts) == 2 and text:
         dev_name = parts[1]
         addr, _ = self._resolve_silent(dev_name)
         ns_filter = self.device_index.caps_for(addr) if addr else None
         candidates = self.registry.commands(ns_filter)
         return [c for c in candidates if c.lower().startswith(text.lower())]
      if len(parts) == 3 and text:
         cmd_name = parts[2]
         return [p for p in self.registry.method_params(cmd_name)
                 if p.lower().startswith(text.lower())]
      return []

   def do_scenes(self, arg):
      """List scenes"""
      try:
         scenes = self._run(self.client.list_scenes())
         if not scenes:
            print("No scenes.")
            return
         for s in scenes:
            name = s.get("scene:name", "?")
            addr = s.get("base:address", "")
            print(f"  {BOLD}{name}{RESET}  {DIM}{addr}{RESET}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_fire(self, arg):
      """fire <scene-name> — Fire a scene"""
      query = arg.strip()
      if not query:
         print("Usage: fire <scene-name>")
         return
      try:
         scenes = self._run(self.client.list_scenes())
         addr = None
         q = query.lower()
         for s in scenes:
            if s.get("scene:name", "").lower() == q or s.get("base:address") == query:
               addr = s.get("base:address")
               break
         if not addr:
            matches = [s for s in scenes if q in s.get("scene:name", "").lower()]
            if len(matches) == 1:
               addr = matches[0].get("base:address")
            elif len(matches) > 1:
               print(f"{YELLOW}Ambiguous:{RESET}")
               for s in matches:
                  print(f"  {s.get('scene:name')}")
               return
         if not addr:
            print(f"{RED}No scene matching '{query}'{RESET}")
            return
         self._run(self.client.send_command(addr, "scene:Fire"))
         print(f"{GREEN}Fired.{RESET}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_rules(self, arg):
      """List rules"""
      try:
         rules = self._run(self.client.list_rules())
         if not rules:
            print("No rules.")
            return
         for r in rules:
            name = r.get("rule:name", "?")
            state = r.get("rule:state", "")
            print(f"  {state_color(state)}{name}{RESET}  {DIM}{state}{RESET}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_subsystems(self, arg):
      """List subsystems"""
      try:
         subs = self._run(self.client.list_subsystems())
         if not subs:
            print("No subsystems.")
            return
         for s in subs:
            name = s.get("subs:name", s.get("base:type", "?"))
            state = s.get("subs:state", "")
            print(f"  {state_color(state)}{name}{RESET}  {DIM}{state}{RESET}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_hub(self, arg):
      """Show hub info"""
      try:
         hub = self._run(self.client.get_hub())
         for key in sorted(hub.keys()):
            print(f"  {DIM}{key:<35}{RESET} {hub[key]}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_places(self, arg):
      """List places"""
      places = self.client.get_places()
      if not places:
         print("No places in session info.")
         return
      for p in places:
         name = p.get("placeName", p.get("name", "?"))
         pid = p.get("placeId", "")
         active = f" {GREEN}*{RESET}" if pid == self.client.place_id else ""
         print(f"  {name}  {DIM}{pid}{RESET}{active}")

   def do_people(self, arg):
      """List people"""
      try:
         people = self._run(self.client.list_people())
         for p in people:
            name = f"{p.get('person:firstName', '')} {p.get('person:lastName', '')}".strip()
            email = p.get("person:email", "")
            print(f"  {BOLD}{name}{RESET}  {email}")
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_listen(self, arg):
      """listen [device] — Stream events (Ctrl-C to stop). Optionally filter to one device."""
      parts = self._parse_line(arg)
      filter_addr = None
      if parts:
         filter_addr, _ = self._resolve(parts[0])
         if not filter_addr:
            return
         print(f"{DIM}Listening for events on {parts[0]}... (Ctrl-C to stop){RESET}")
      else:
         print(f"{DIM}Listening... (Ctrl-C to stop){RESET}")
      try:
         def on_msg(msg):
            src = msg.get("headers", {}).get("source", "")
            if filter_addr and filter_addr not in src:
               return
            mtype = msg.get("type", "?")
            attrs = msg.get("payload", {}).get("attributes", {})
            print(f"  {CYAN}{mtype}{RESET} {DIM}{src}{RESET}")
            if attrs:
               for k, v in attrs.items():
                  print(f"    {DIM}{k}{RESET} = {v}")
         self._run(self.client.listen(on_msg))
      except KeyboardInterrupt:
         print()

   def complete_listen(self, text, line, begidx, endidx):
      if not text:
         return []
      return [n for n in self.device_index.names()
              if n.lower().startswith(text.lower())]

   def do_request(self, arg):
      """request <destination> <command> [key=val ...] — Raw platform request"""
      parts = self._parse_line(arg)
      if len(parts) < 2:
         print("Usage: request <destination> <command> [key=val ...]")
         return
      try:
         attrs = parse_kv(parts[2:]) if len(parts) > 2 else {}
         result = self._run(self.client.send_command(parts[0], parts[1], attrs))
         ppjson(result)
      except Exception as e:
         print(f"{RED}{e}{RESET}")

   def do_caps(self, arg):
      """caps [namespace] — Browse capabilities"""
      ns = arg.strip()
      if not ns:
         for ns_key in sorted(self.registry.capabilities):
            cap = self.registry.capabilities[ns_key]
            print(f"  {BOLD}{ns_key:<12}{RESET} {cap.name}")
         return
      cap = self.registry.capabilities.get(ns)
      if not cap:
         print(f"{RED}Unknown: {ns}{RESET}")
         return
      print(f"\n{BOLD}{cap.name}{RESET} ({ns})")
      if cap.attributes:
         print(f"\n  Attributes:")
         for name, attr in sorted(cap.attributes.items()):
            rw = attr.readwrite
            vals = f" [{attr.values}]" if attr.values else ""
            print(f"    {CYAN}{ns}:{name}{RESET}  {attr.type} ({rw}){vals}")
            if attr.description:
               print(f"      {DIM}{attr.description[:90]}{RESET}")
      if cap.methods:
         print(f"\n  Commands:")
         for name, m in sorted(cap.methods.items()):
            params = ", ".join(f"{p.name}:{p.type}" for p in m.parameters)
            print(f"    {CYAN}{ns}:{name}{RESET}({params})")
            if m.description:
               print(f"      {DIM}{m.description[:90]}{RESET}")
      print()

   def complete_caps(self, text, line, begidx, endidx):
      if not text:
         return []
      return [ns for ns in self.registry.capabilities if ns.startswith(text)]

   def do_logout(self, arg):
      """Log out and clear session"""
      self.client.logout()
      print(f"{GREEN}Logged out.{RESET}")
      return True

   def do_quit(self, arg):
      """Exit"""
      self._run(self.client.disconnect())
      return True

   do_exit = do_quit
   do_EOF = do_quit
