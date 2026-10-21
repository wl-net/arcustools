"""Entry point for the oculus CLI."""

import asyncio
import getpass
import sys

from .caps import load_registry
from .client import ArcusClient, load_session, save_session, clear_session
from .shell import OculusShell

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def do_login_flow():
   session = load_session()
   default_host = session.get("host", "https://localhost:8081") if session else "https://localhost:8081"
   host = input(f"Host [{default_host}]: ").strip() or default_host
   user = input("Username: ")
   password = getpass.getpass("Password: ")

   client = ArcusClient(host)
   token = client.login(user, password)

   loop = asyncio.new_event_loop()
   msg = loop.run_until_complete(client.connect())
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
      loop.run_until_complete(client.request("SERV:sess:", "sess:SetActivePlace",
                                             {"placeId": place_id}))
      client.place_id = place_id

   save_session({"host": host, "token": token, "user": user, "place_id": place_id})
   loop.run_until_complete(client.disconnect())
   loop.close()
   print(f"{GREEN}Logged in.{RESET}")


def main():
   import argparse
   parser = argparse.ArgumentParser(prog="oculus",
                                    description="Arcus platform CLI")
   parser.add_argument("-c", "--command", help="Run a single command and exit")
   parser.add_argument("--login", action="store_true", help="Log in")
   parser.add_argument("--logout", action="store_true", help="Log out")
   parser.add_argument("--caps-dir", help="Path to capability XMLs directory")
   args = parser.parse_args()

   if args.login:
      do_login_flow()
      return

   if args.logout:
      session = load_session()
      if session:
         ArcusClient(session.get("host", ""), session.get("token")).logout()
      clear_session()
      print(f"{GREEN}Logged out.{RESET}")
      return

   session = load_session()
   if not session or "token" not in session:
      print("Not logged in.")
      do_login_flow()
      session = load_session()

   client = ArcusClient(
      host=session["host"],
      session_token=session["token"],
      place_id=session.get("place_id"),
   )
   extra = [args.caps_dir] if args.caps_dir else None
   registry = load_registry(extra_paths=extra)
   shell = OculusShell(client, registry)

   if args.command:
      shell.preloop()
      shell.onecmd(args.command)
      shell._run(client.disconnect())
   else:
      try:
         shell.cmdloop()
      except KeyboardInterrupt:
         print()
      finally:
         shell._run(client.disconnect())
