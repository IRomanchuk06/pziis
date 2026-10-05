#!/usr/bin/env python3
"""Генерация /etc/suricata/generated.yaml из штатного suricata.yaml образа.

Точечные изменения:
  * HOME_NET -> подсеть защищаемого сервера (secure-сеть compose);
  * af-packet: один интерфейс (outside, eth0 suricata), threads=1;
  * pcap-захват отключён (иначе пакеты считались бы дважды);
  * rule-files: local.rules + suricata.rules (ET Open), если загружены.
"""
import os
import sys

import yaml

IFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
HOME_NET = os.environ.get("HOME_NET_CIDR", "172.29.100.0/24")

SRC = "/etc/suricata/suricata.yaml"
DST = "/etc/suricata/generated.yaml"

with open(SRC) as f:
    cfg = yaml.safe_load(f)

# --- переменные (HOME_NET = защищаемая сеть) ---
cfg["vars"]["address-groups"]["HOME_NET"] = "[%s]" % HOME_NET
cfg["vars"]["address-groups"]["EXTERNAL_NET"] = "!$HOME_NET"

# --- захват: af-packet на outside-интерфейсе ---
af = cfg.get("af-packet")
if isinstance(af, list) and af:
    entry = af[0]
    entry["interface"] = IFACE
    entry["threads"] = 1
    cfg["af-packet"] = [entry]
cfg["pcap"] = []

# --- правила ---
cfg["default-rule-path"] = "/etc/suricata/rules"
rule_files = ["local.rules"]
if os.path.exists("/etc/suricata/rules/suricata.rules"):
    rule_files.insert(0, "suricata.rules")
cfg["rule-files"] = rule_files
cfg["threshold-file"] = "/etc/suricata/rules/threshold.config"

# --- выходные логи: fast.log и eve.json включены принудительно ---
for out in cfg.get("outputs", []):
    if isinstance(out, dict) and "fast" in out:
        out["fast"]["enabled"] = True
    if isinstance(out, dict) and "eve-log" in out:
        out["eve-log"]["enabled"] = True

with open(DST, "w") as f:
    # Suricata требует в начале файла директиву %YAML 1.1 и маркер ---
    f.write("%YAML 1.1\n---\n")
    yaml.dump(cfg, f, default_flow_style=False, width=4096)

print("[genconf] iface=%s HOME_NET=%s rule-files=%s" % (IFACE, HOME_NET, rule_files))
