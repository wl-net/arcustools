"""Capability XML parser for Arcus platform capability definitions."""

import xml.etree.ElementTree as ET
from pathlib import Path

CAP_NS = "{http://www.arcussmarthome.com/schema/capability/1.0.0}"
SVC_NS = "{http://www.arcussmarthome.com/schema/service/1.0.0}"


class CapabilityRegistry:
   def __init__(self):
      self.capabilities = {}   # namespace -> CapInfo
      self.name_to_ns = {}     # "Switch" -> "swit"

   def load_dir(self, cap_dir):
      cap_path = Path(cap_dir)
      if not cap_path.is_dir():
         return
      for xml_file in cap_path.glob("*.xml"):
         if xml_file.name.endswith(".xsd"):
            continue
         try:
            self._parse_file(xml_file)
         except Exception:
            pass

   def _parse_file(self, xml_file):
      tree = ET.parse(xml_file)
      root = tree.getroot()
      ns_attr = root.get("namespace")
      name_attr = root.get("name")
      if not ns_attr:
         return

      cap = CapInfo(name=name_attr, namespace=ns_attr)
      self.capabilities[ns_attr] = cap
      if name_attr:
         self.name_to_ns[name_attr] = ns_attr

      for el in list(root.iter(f"{CAP_NS}attribute")) + list(root.iter(f"{SVC_NS}attribute")):
         a = AttrInfo(
            name=el.get("name", ""), type=el.get("type", "string"),
            readwrite=el.get("readwrite", "r"), values=el.get("values", ""),
            description=el.get("description", ""),
         )
         cap.attributes[a.name] = a

      for el in list(root.iter(f"{CAP_NS}method")) + list(root.iter(f"{SVC_NS}method")):
         m = MethodInfo(name=el.get("name", ""), description=el.get("description", ""))
         for p in list(el.iter(f"{CAP_NS}parameter")) + list(el.iter(f"{SVC_NS}parameter")):
            m.parameters.append(ParamInfo(
               name=p.get("name", ""), type=p.get("type", "string"),
               description=p.get("description", ""),
            ))
         cap.methods[m.name] = m

   def namespaces_for_device(self, device_attrs):
      return [self.name_to_ns[c] for c in device_attrs.get("base:caps", [])
              if c in self.name_to_ns]

   def rw_attributes(self, namespaces=None):
      result = []
      for ns, cap in self.capabilities.items():
         if namespaces and ns not in namespaces:
            continue
         for name, attr in cap.attributes.items():
            if "w" in attr.readwrite:
               result.append(f"{ns}:{name}")
      return sorted(result)

   def commands(self, namespaces=None):
      result = []
      for ns, cap in self.capabilities.items():
         if namespaces and ns not in namespaces:
            continue
         for name in cap.methods:
            result.append(f"{ns}:{name}")
      return sorted(result)

   def method_params(self, qualified_command):
      if ":" not in qualified_command:
         return []
      ns, method = qualified_command.split(":", 1)
      cap = self.capabilities.get(ns)
      if not cap:
         return []
      m = cap.methods.get(method)
      if not m:
         return []
      return [f"{p.name}=" for p in m.parameters]


class CapInfo:
   def __init__(self, name, namespace):
      self.name = name
      self.namespace = namespace
      self.attributes = {}
      self.methods = {}


class AttrInfo:
   def __init__(self, name, type, readwrite, values, description):
      self.name = name
      self.type = type
      self.readwrite = readwrite
      self.values = values
      self.description = description


class MethodInfo:
   def __init__(self, name, description):
      self.name = name
      self.description = description
      self.parameters = []


class ParamInfo:
   def __init__(self, name, type, description):
      self.name = name
      self.type = type
      self.description = description


def load_registry(extra_paths=None):
   """Load capability XMLs from known locations."""
   reg = CapabilityRegistry()

   search_paths = [
      Path.home() / ".oculus" / "capabilities",
      Path.home() / "projects" / "arcusplatform" / "common" / "arcus-model" / "src" / "main" / "resources" / "capability",
   ]
   if extra_paths:
      search_paths = [Path(p) for p in extra_paths] + search_paths

   for cap_dir in search_paths:
      if cap_dir.is_dir():
         reg.load_dir(cap_dir)
         svc_dir = cap_dir.parent / "service"
         if svc_dir.is_dir():
            reg.load_dir(svc_dir)
         break

   return reg
