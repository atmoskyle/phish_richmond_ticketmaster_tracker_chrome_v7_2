#!/usr/bin/env python3
"""
Phish MSG Ticketmaster monitor — Chrome v7.3 facets-authoritative

Signals:
1) Ticketmaster EventFacets responses captured passively from the event page.
   Supports both services.ticketmaster.com and offeradapter.ticketmaster.com.
2) AVSC binary activity from pubapi.ticketmaster.com/avsc/events/<EVENT_ID>.

Decision hierarchy:
- EventFacets is authoritative for purchasable inventory.
- Alert only when Facets contains an explicit positive quantity, concrete
  standard-primary inventory details, and no Platinum/resale ambiguity.
- Valid Facets with [] => EMPTY (no alert), even if AVSC has active positions.
- AVSC activity by itself => AVSC_ACTIVITY (log only, never alert).
- A material AVSC fingerprint change can trigger a short burst of page refreshes
  to try to capture a confirming Facets response.
- Missing/undecodable signals never mean sold out.

Alert-only: no carting, purchasing, queue bypass, or CAPTCHA bypass.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import platform
import random
import re
import smtplib
import ssl
import struct
import subprocess
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config.json"
CONFIG: Dict[str, Any] = {}
STATE: Dict[str, Any] = {}

SERIAL_COOKIE = 12347
SERIAL_COOKIE_NO_RUN = 12346
ARRAY_LIMIT = 4096
MAX_AVSC_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BODY_BYTES = 32 * 1024 * 1024
MAX_ROARING_CONTAINERS = 65536
MAX_ROARING_VALUES = 1_000_000


@dataclass
class Event:
    name: str
    dates: str
    url: str
    event_id: str
    handle: Optional[str] = None
    manifest: Optional[Dict[str, Any]] = None


# ---------- Utilities ----------

def now_iso() -> str:
    return datetime.now(monitor_timezone()).isoformat(timespec="seconds")


def monitor_timezone() -> ZoneInfo:
    return ZoneInfo(str(CONFIG.get("timezone", "America/New_York")))


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        if default is None:
            raise
        logging.warning("Ignoring invalid JSON in %s; using an empty default", path)
        return default


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    tmp.replace(path)


def configured_path(key: str, default: str) -> Path:
    """Resolve configured data paths relative to this script, not the shell CWD."""
    path = Path(CONFIG.get(key, default)).expanduser()
    return path if path.is_absolute() else ROOT / path


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",", ":"), default=str) + "\n")


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


def extract_event_id(url: str) -> str:
    m = re.search(r"/event/([A-Za-z0-9]+)", url)
    if not m:
        raise ValueError(f"Could not extract Ticketmaster event ID from {url}")
    return m.group(1)


def build_events(cfg: Dict[str, Any]) -> List[Event]:
    events = []
    for item in cfg["events"]:
        url = item["url"].strip()
        events.append(Event(
            name=item["name"],
            dates=item.get("dates", ""),
            url=url,
            event_id=item.get("event_id") or extract_event_id(url),
        ))
    return events


# ---------- Portable Roaring decoder ----------

def parse_roaring(buf: bytes) -> Set[int]:
    if len(buf) > MAX_AVSC_BYTES:
        raise ValueError("Roaring payload exceeds configured size limit")
    if len(buf) < 8:
        raise ValueError("Roaring payload too small")

    pos = 0
    cookie = struct.unpack_from("<I", buf, pos)[0]
    pos += 4

    if cookie == SERIAL_COOKIE_NO_RUN:
        size = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        if size > MAX_ROARING_CONTAINERS:
            raise ValueError("Roaring container count exceeds limit")
        run_bits = [False] * size
        has_offsets = True
    elif (cookie & 0xFFFF) == SERIAL_COOKIE:
        size = (cookie >> 16) + 1
        if size > MAX_ROARING_CONTAINERS:
            raise ValueError("Roaring container count exceeds limit")
        nbytes = (size + 7) // 8
        if pos + nbytes > len(buf):
            raise ValueError("Roaring run bitmap exceeds buffer")
        rb = buf[pos:pos+nbytes]
        pos += nbytes
        run_bits = [bool(rb[i//8] & (1 << (i % 8))) for i in range(size)]
        has_offsets = size >= 4
    else:
        raise ValueError(f"Unknown Roaring cookie {cookie}")

    desc = []
    for _ in range(size):
        if pos + 4 > len(buf):
            raise ValueError("Roaring description exceeds buffer")
        key, card_minus_1 = struct.unpack_from("<HH", buf, pos)
        pos += 4
        desc.append((key, card_minus_1 + 1))

    if sum(cardinality for _, cardinality in desc) > MAX_ROARING_VALUES:
        raise ValueError("Roaring cardinality exceeds configured limit")

    if has_offsets:
        skip = 4 * size
        if pos + skip > len(buf):
            raise ValueError("Roaring offsets exceed buffer")
        pos += skip

    values: Set[int] = set()

    for i, (key, cardinality) in enumerate(desc):
        high = key << 16

        if run_bits[i]:
            if pos + 2 > len(buf):
                raise ValueError("Roaring run count exceeds buffer")
            nruns = struct.unpack_from("<H", buf, pos)[0]
            pos += 2
            produced = 0
            for _ in range(nruns):
                if pos + 4 > len(buf):
                    raise ValueError("Roaring run exceeds buffer")
                start, length = struct.unpack_from("<HH", buf, pos)
                pos += 4
                end = start + length
                if end > 0xFFFF:
                    raise ValueError("Roaring run exceeds 16-bit container")
                for x in range(start, start + length + 1):
                    values.add(high + x)
                produced += length + 1
            if produced != cardinality:
                raise ValueError("Roaring run cardinality mismatch")

        elif cardinality <= ARRAY_LIMIT:
            need = cardinality * 2
            if pos + need > len(buf):
                raise ValueError("Roaring array exceeds buffer")
            lows = struct.unpack_from("<" + "H"*cardinality, buf, pos)
            pos += need
            for low in lows:
                values.add(high + low)

        else:
            need = 8192
            if pos + need > len(buf):
                raise ValueError("Roaring bitmap exceeds buffer")
            words = struct.unpack_from("<" + "Q"*1024, buf, pos)
            pos += need
            produced = 0
            for wi, word in enumerate(words):
                w = word
                while w:
                    lowbit = w & -w
                    bit = lowbit.bit_length() - 1
                    values.add(high + wi*64 + bit)
                    produced += 1
                    w &= w - 1
            if produced != cardinality:
                raise ValueError("Roaring bitmap cardinality mismatch")

    return values


# ---------- Minimal FlatBuffers reader ----------

def table_info(buf: bytes, table: int) -> Dict[str, Any]:
    if table < 4 or table + 4 > len(buf):
        raise ValueError("Invalid FlatBuffer table")
    soff = struct.unpack_from("<i", buf, table)[0]
    vtable = table - soff
    if vtable < 0 or vtable + 4 > len(buf):
        raise ValueError("Invalid FlatBuffer vtable")
    vlen, object_len = struct.unpack_from("<HH", buf, vtable)
    if vlen < 4 or vlen % 2 or vtable + vlen > len(buf):
        raise ValueError("Invalid FlatBuffer vtable length")
    if object_len < 4 or table + object_len > len(buf):
        raise ValueError("Invalid FlatBuffer object length")
    n = (vlen - 4) // 2
    fields = list(struct.unpack_from("<" + "H"*n, buf, vtable + 4))
    if any(off >= object_len for off in fields if off):
        raise ValueError("FlatBuffer field offset exceeds table")
    return {"fields": fields, "object_len": object_len}


def root_table(buf: bytes) -> int:
    if len(buf) < 8:
        raise ValueError("FlatBuffer too small")
    root = struct.unpack_from("<I", buf, 0)[0]
    if root < 4 or root + 4 > len(buf):
        raise ValueError("Invalid FlatBuffer root offset")
    return root


def field_pos(buf: bytes, table: int, field_index: int) -> Optional[int]:
    info = table_info(buf, table)
    if field_index >= len(info["fields"]):
        return None
    off = info["fields"][field_index]
    if not off:
        return None
    pos = table + off
    if pos >= table + info["object_len"] or pos >= len(buf):
        raise ValueError("FlatBuffer field exceeds table")
    return pos


def uoffset_target(buf: bytes, pos: int) -> int:
    if pos + 4 > len(buf):
        raise ValueError("uoffset exceeds buffer")
    offset = struct.unpack_from("<I", buf, pos)[0]
    target = pos + offset
    if offset == 0 or target >= len(buf):
        raise ValueError("Invalid FlatBuffer uoffset target")
    return target


def vector_info(buf: bytes, field_position: int) -> Tuple[int, int]:
    vec = uoffset_target(buf, field_position)
    if vec + 4 > len(buf):
        raise ValueError("vector exceeds buffer")
    length = struct.unpack_from("<I", buf, vec)[0]
    if length > MAX_ROARING_VALUES:
        raise ValueError("FlatBuffer vector exceeds configured limit")
    return vec, length


def vector_of_tables(buf: bytes, field_position: int) -> List[int]:
    vec, length = vector_info(buf, field_position)
    base = vec + 4
    if base + 4*length > len(buf):
        raise ValueError("table vector exceeds buffer")
    out = []
    for i in range(length):
        ep = base + 4*i
        out.append(ep + struct.unpack_from("<I", buf, ep)[0])
    return out


def byte_vector(buf: bytes, field_position: int) -> bytes:
    vec, length = vector_info(buf, field_position)
    start = vec + 4
    end = start + length
    if end > len(buf) or length > MAX_AVSC_BYTES:
        raise ValueError("byte vector exceeds buffer")
    return buf[start:end]


def fb_string(buf: bytes, field_position: Optional[int]) -> Optional[str]:
    if field_position is None:
        return None
    target = uoffset_target(buf, field_position)
    if target + 4 > len(buf):
        return None
    length = struct.unpack_from("<I", buf, target)[0]
    start = target + 4
    end = start + length
    if end > len(buf) or length > MAX_AVSC_BYTES:
        return None
    try:
        return buf[start:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_group_bitmap_vector(buf: bytes, pos: Optional[int]) -> Dict[int, Set[int]]:
    if pos is None:
        return {}
    out: Dict[int, Set[int]] = {}
    for table in vector_of_tables(buf, pos):
        group_pos = field_pos(buf, table, 0)
        bitmap_pos = field_pos(buf, table, 1)
        if group_pos is None or bitmap_pos is None:
            continue
        gid = struct.unpack_from("<I", buf, group_pos)[0]
        out[gid] = parse_roaring(byte_vector(buf, bitmap_pos))
    return out


def parse_offer_metadata(buf: bytes, event_table: int) -> List[Dict[str, str]]:
    """Decode the AVSC event offer definitions we need for ticket-type resolution."""
    out: List[Dict[str, str]] = []
    try:
        offers_pos = field_pos(buf, event_table, 8)
        if offers_pos is None:
            return []
        for t in vector_of_tables(buf, offers_pos):
            # Observed on the Jacksonville positive control:
            # field 4=ticketTypeId, 5=short code, 6=offer name, 7=description.
            item = {
                "ticket_type_id": fb_string(buf, field_pos(buf, t, 4)) or "",
                "code": fb_string(buf, field_pos(buf, t, 5)) or "",
                "name": fb_string(buf, field_pos(buf, t, 6)) or "",
                "description": fb_string(buf, field_pos(buf, t, 7)) or "",
            }
            if any(item.values()):
                out.append(item)
    except Exception as exc:
        logging.warning("AVSC offer metadata could not be decoded: %s", exc)
    return out


def parse_offer_names(buf: bytes, event_table: int) -> List[str]:
    names: List[str] = []
    for item in parse_offer_metadata(buf, event_table):
        name = item.get("name")
        if name and name not in names:
            names.append(name)
    return names


def parse_availability(buf: bytes, manifest: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if len(buf) > MAX_AVSC_BYTES:
        raise ValueError("AVSC payload exceeds configured size limit")
    root = root_table(buf)
    event_pos = field_pos(buf, root, 0)
    seat_pos = field_pos(buf, root, 1)
    section_pos = field_pos(buf, root, 2)
    if not event_pos or not seat_pos or not section_pos:
        raise ValueError("Unexpected AVSC root schema")

    event_table = uoffset_target(buf, event_pos)
    seat_table = uoffset_target(buf, seat_pos)
    section_table = uoffset_target(buf, section_pos)

    seat_groups = parse_group_bitmap_vector(buf, field_pos(buf, seat_table, 4))
    section_groups = parse_group_bitmap_vector(buf, field_pos(buf, section_table, 2))

    seat_indices: Set[int] = set()
    for vals in seat_groups.values():
        seat_indices.update(vals)

    section_indices: Set[int] = set()
    for vals in section_groups.values():
        section_indices.update(vals)

    section_names: List[str] = []
    if manifest:
        sections = manifest.get("manifestSections", []) or []
        for idx in sorted(section_indices):
            if 0 <= idx < len(sections):
                section_names.append(str(sections[idx].get("name", f"#{idx}")))
            else:
                section_names.append(f"#{idx}")

    ga_like = [s for s in section_names if re.search(r"(^GA\b|GAFLR|GENERAL|PIT)", s, re.I)]
    offer_metadata = parse_offer_metadata(buf, event_table)
    offers = [x["name"] for x in offer_metadata if x.get("name")]
    ticket_type_names = {
        x["ticket_type_id"]: x["name"]
        for x in offer_metadata
        if x.get("ticket_type_id") and x.get("name")
    }

    normalized = {
        "seat_groups": {str(k): sorted(v) for k, v in sorted(seat_groups.items())},
        "section_groups": {str(k): sorted(v) for k, v in sorted(section_groups.items())},
    }
    fp = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    activity = bool(seat_indices or section_indices)
    return {
        # AVSC activity is upstream evidence, not proof that a consumer ticket
        # can be purchased, so it deliberately avoids the word AVAILABLE.
        "status": "ACTIVITY" if activity else "EMPTY",
        "activity": activity,
        "available": None,
        "reserved_available": len(seat_indices),
        "available_section_count": len(section_indices),
        "available_sections": section_names,
        "ga_like_sections": ga_like,
        "offer_names": list(dict.fromkeys(offers)),
        "offer_metadata": offer_metadata,
        "ticket_type_names": ticket_type_names,
        "fingerprint": fp,
    }


# ---------- Facets classifier ----------

def _norm_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _facet_text(facet: Dict[str, Any]) -> str:
    """Flatten one facet for conservative Platinum/nonstandard detection."""
    chunks: List[str] = []
    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                if str(k).lower() in {"offers", "places", "placegroups"}:
                    continue
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        elif isinstance(v, (str, int, float, bool)):
            chunks.append(str(v))
    walk(facet)
    return " ".join(chunks).lower()


def _facet_count(facet: Dict[str, Any]) -> Optional[int]:
    if "count" not in facet or isinstance(facet.get("count"), bool):
        return None
    try:
        value = facet["count"]
        count = int(value)
        if isinstance(value, float) and value != count:
            return None
        if isinstance(value, str) and value.strip() != str(count):
            return None
        return max(0, count)
    except Exception:
        return None


def _has_concrete_inventory(facet: Dict[str, Any]) -> bool:
    return bool(
        _norm_list(facet.get("offers"))
        or _norm_list(facet.get("ticketTypes"))
        or _norm_list(facet.get("ticketTypeIds"))
        or _norm_list(facet.get("ticketTypeId"))
        or facet.get("section")
        or facet.get("area")
        or facet.get("places")
        or facet.get("placeGroups")
        or facet.get("placegroups")
    )


def _price_text(facet: Dict[str, Any]) -> str:
    ranges = facet.get("totalPriceRange") or facet.get("listPriceRange") or []
    vals: List[Tuple[float, float]] = []
    if isinstance(ranges, dict):
        ranges = [ranges]
    for r in ranges if isinstance(ranges, list) else []:
        if not isinstance(r, dict):
            continue
        lo, hi = r.get("min"), r.get("max")
        try:
            if lo is not None and hi is not None:
                vals.append((float(lo), float(hi)))
        except Exception:
            pass
    if not vals:
        return ""
    lo = min(x[0] for x in vals); hi = max(x[1] for x in vals)
    return f"${lo:.2f}" if lo == hi else f"${lo:.2f}-${hi:.2f}"


def _embedded_offer_map(body: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    emb = body.get("_embedded") or {}
    candidates: List[Any] = []
    if isinstance(emb, dict):
        for key in ("offer", "offers"):
            v = emb.get(key)
            if isinstance(v, list):
                candidates.extend(v)
    out: Dict[str, Dict[str, Any]] = {}
    for o in candidates:
        if isinstance(o, dict) and o.get("offerId"):
            out[str(o["offerId"])] = o
    return out


def _has_standard_label(text: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    return any(label in normalized for label in (
        "standard admission", "standard reserved", "standard floor",
        "general admission", "2 day ticket", "two day ticket",
        "4 day ticket", "four day ticket",
    ))


def _offer_record_kind(o: Dict[str, Any]) -> str:
    inv = str(o.get("inventoryType") or "").lower()
    text = " ".join(str(o.get(k) or "") for k in (
        "name", "description", "ticketTypeUnsoldQualifier", "offerName", "offerDescription"
    )).lower()
    if inv == "resale" or "resale" in text:
        return "resale"
    if "platinum" in text:
        return "platinum"
    # Exclude protected/presale/VIP products from face-value standard alerts.
    excluded = ("presale", "preferred", "cardmember", "vip", "package", "soundcheck")
    if any(x in text for x in excluded):
        return "nonstandard"
    if inv in ("", "primary") and _has_standard_label(text):
        return "standard_primary"
    if inv in ("", "primary"):
        return "primary_unresolved"
    return "nonprimary"


def _known_ticket_type_names(facet: Dict[str, Any], ticket_type_names: Dict[str, str]) -> List[str]:
    if not ticket_type_names:
        return []
    found: List[str] = []
    known = set(ticket_type_names)
    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values(): walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v: walk(x)
        elif isinstance(v, (str, int)):
            key = str(v)
            if key in known and ticket_type_names[key] not in found:
                found.append(ticket_type_names[key])
    walk(facet)
    return found


def _ticket_name_kind(names: List[str]) -> Optional[str]:
    if not names:
        return None
    lowered = [x.lower() for x in names]
    excluded = ("platinum", "presale", "preferred", "cardmember", "vip", "package", "soundcheck")
    kinds = set()
    for x in lowered:
        if "platinum" in x:
            kinds.add("platinum")
        elif any(bad in x for bad in excluded):
            kinds.add("nonstandard")
        elif _has_standard_label(x):
            kinds.add("standard_primary")
        else:
            kinds.add("primary_unresolved")
    return next(iter(kinds)) if len(kinds) == 1 else "primary_unresolved"


def _classify_one_facet(
    facet: Dict[str, Any],
    offer_map: Dict[str, Dict[str, Any]],
    ticket_type_names: Dict[str, str],
) -> str:
    """Resolve a facet to standard primary vs Platinum/resale/nonstandard."""
    if facet.get("available") is False:
        return "unavailable"

    inv = {x.lower() for x in _norm_list(facet.get("inventoryTypes"))}
    text = _facet_text(facet)
    count = _facet_count(facet)
    if count is None:
        return "primary_unresolved"
    if count <= 0:
        return "unavailable"
    if "resale" in inv or "verified resale" in text or "fan-to-fan resale" in text:
        return "resale"
    if inv and "primary" not in inv:
        return "nonprimary"
    if not _has_concrete_inventory(facet):
        return "primary_unresolved"

    # Best case: Facets embedded the exact offer objects. Official Platinum is
    # inventoryType=primary + offerType=standard, so the NAME is decisive.
    referenced_offers = set(_norm_list(facet.get("offers")))
    if referenced_offers:
        resolved = [offer_map[x] for x in referenced_offers if x in offer_map]
        if len(resolved) == len(referenced_offers):
            kinds = {_offer_record_kind(x) for x in resolved}
            return next(iter(kinds)) if len(kinds) == 1 else "primary_unresolved"

    # Next best: map Facets' ticket-type IDs against AVSC's offer definitions.
    ticket_refs: Set[str] = set()
    for key in ("ticketTypes", "ticketTypeIds", "ticketTypeId"):
        ticket_refs.update(_norm_list(facet.get(key)))
    if ticket_refs:
        if not ticket_type_names or any(ref not in ticket_type_names for ref in ticket_refs):
            return "primary_unresolved"
        names = list(dict.fromkeys(ticket_type_names[ref] for ref in sorted(ticket_refs)))
    else:
        names = _known_ticket_type_names(facet, ticket_type_names)
    tk = _ticket_name_kind(names)
    if tk:
        return tk
    if referenced_offers:
        return "primary_unresolved"

    # Direct labels sometimes appear in the facet itself.
    if "platinum" in text:
        return "platinum"
    excluded = ("presale", "preferred", "cardmember", "vip", "package", "soundcheck")
    if any(x in text for x in excluded):
        return "nonstandard"
    if _has_standard_label(text):
        return "standard_primary"

    # Do NOT assume primary + offerType=standard means face-value standard:
    # Ticketmaster also represents Official Platinum that way.
    if "primary" in inv:
        return "primary_unresolved"
    return "unavailable"


def _facet_detail(f: Dict[str, Any]) -> str:
    qty = _facet_count(f)
    inv = ",".join(_norm_list(f.get("inventoryTypes"))) or "primary?"
    section = f.get("section") or f.get("area") or "?"
    price = _price_text(f)
    offers = _norm_list(f.get("offers"))
    bits = [f"Qty {qty if qty is not None else '?'}", f"inv={inv}", f"section={section}"]
    if price:
        bits.append(price)
    if offers:
        bits.append(f"offer={offers[0]}")
    return " | ".join(bits)


def _body_score(body: Dict[str, Any]) -> Tuple[int, int]:
    facets = [f for f in (body.get("facets") or []) if isinstance(f, dict)]
    useful = sum(
        8 * bool(f.get("inventoryTypes"))
        + 5 * bool(f.get("offers"))
        + 3 * ("count" in f)
        + 2 * bool(f.get("section") or f.get("area") or f.get("places") or f.get("placeGroups"))
        + 2 * bool(f.get("ticketTypes") or f.get("ticketTypeIds") or f.get("ticketTypeId"))
        + 2 * bool(f.get("listPriceRange") or f.get("totalPriceRange"))
        for f in facets
    )
    return useful, len(facets)


def _canonical(value: Any) -> Any:
    """Normalize nested API data so ordering changes do not look material."""
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple, set)):
        items = [_canonical(x) for x in value]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
    return value


def _facet_fingerprint_material(facet: Dict[str, Any], kind: str) -> Dict[str, Any]:
    keys = (
        "available", "count", "inventoryTypes", "offers", "ticketTypes",
        "ticketTypeIds", "ticketTypeId", "section", "area", "listPriceRange", "totalPriceRange",
    )
    return {
        "kind": kind,
        **{key: _canonical(facet[key]) for key in keys if key in facet},
    }


def classify_facets(
    bodies: List[Dict[str, Any]],
    ticket_type_names: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    ticket_type_names = ticket_type_names or {}
    if not bodies:
        return {
            "status": "NO_SIGNAL", "available": None, "response_count": 0,
            "facet_lengths": [], "fingerprint": None, "alert_fingerprint": None, "positive_bodies": [],
            "standard_primary_facets": [], "platinum_facets": [],
            "resale_facets": [], "unresolved_primary_facets": [], "details": [],
        }

    lengths = [len(x.get("facets") or []) for x in bodies]
    richest_body = max(bodies, key=_body_score)
    richest = richest_body.get("facets") or []
    # Merge any embedded offer records seen in any captured Facets response.
    offer_map: Dict[str, Dict[str, Any]] = {}
    for body in bodies:
        offer_map.update(_embedded_offer_map(body))

    standard: List[Dict[str, Any]] = []
    platinum: List[Dict[str, Any]] = []
    resale: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    other: List[Dict[str, Any]] = []
    classified: List[Tuple[Dict[str, Any], str]] = []
    for f in richest:
        if not isinstance(f, dict):
            continue
        kind = _classify_one_facet(f, offer_map, ticket_type_names)
        classified.append((f, kind))
        if kind == "standard_primary": standard.append(f)
        elif kind == "platinum": platinum.append(f)
        elif kind == "resale": resale.append(f)
        elif kind == "primary_unresolved": unresolved.append(f)
        elif kind not in {"unavailable"}: other.append(f)

    actual = [f for f, kind in classified if kind != "unavailable"]
    all_material = {
        json.dumps(_facet_fingerprint_material(f, kind), sort_keys=True, separators=(",", ":"))
        for body in bodies
        for f in (body.get("facets") or [])
        if isinstance(f, dict)
        for kind in [_classify_one_facet(f, offer_map, ticket_type_names)]
        if kind != "unavailable"
    }
    fp = hashlib.sha256("\n".join(sorted(all_material)).encode()).hexdigest()
    alert_material = sorted({
        json.dumps(_facet_fingerprint_material(f, "standard_primary"), sort_keys=True, separators=(",", ":"))
        for f in standard
    })
    alert_fp = hashlib.sha256("\n".join(alert_material).encode()).hexdigest() if standard else None
    if standard:
        status, available = "AVAILABLE_STANDARD", True
    elif actual and platinum and len(platinum) == len(actual):
        status, available = "PLATINUM_ONLY", False
    elif actual and resale and len(resale) == len(actual):
        status, available = "RESALE_ONLY", False
    elif unresolved:
        status, available = "PRIMARY_UNRESOLVED", False
    elif actual:
        status, available = "NONSTANDARD_ONLY", False
    else:
        status, available = "EMPTY", False

    return {
        "status": status, "available": available, "response_count": len(bodies),
        "facet_lengths": lengths, "fingerprint": fp, "alert_fingerprint": alert_fp,
        "positive_bodies": [richest_body] if standard else [],
        "standard_primary_facets": standard, "platinum_facets": platinum,
        "resale_facets": resale, "unresolved_primary_facets": unresolved,
        "details": [_facet_detail(f) for f in standard[:20]],
        "resolved_offer_count": len(offer_map),
        "ticket_type_map_count": len(ticket_type_names),
    }


# ---------- Chrome capture ----------

def create_driver(cfg: Dict[str, Any]) -> webdriver.Chrome:
    o = Options()
    if cfg.get("headless", False):
        o.add_argument("--headless=new")
    o.add_argument("--window-size=1440,1000")
    o.add_argument("--disable-notifications")
    o.add_argument("--disable-popup-blocking")
    o.page_load_strategy = "eager"
    o.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    d = webdriver.Chrome(options=o)
    d.set_page_load_timeout(int(cfg.get("page_load_timeout_seconds", 20)))
    d.execute_cdp_cmd("Network.enable", {
        "maxTotalBufferSize": 100000000,
        "maxResourceBufferSize": 50000000,
    })
    return d


def clear_perf_log(driver: webdriver.Chrome) -> None:
    try:
        driver.get_log("performance")
    except Exception:
        pass


def switch(driver: webdriver.Chrome, event: Event) -> None:
    if not event.handle:
        raise RuntimeError(f"No tab for {event.name}")
    driver.switch_to.window(event.handle)


def decode_cdp_body(result: Dict[str, Any]) -> bytes:
    body = result.get("body", "")
    if result.get("base64Encoded", False):
        return base64.b64decode(body)
    return body.encode("utf-8")


def classify_request(host: str, path: str, event_id: str) -> Optional[str]:
    # Ticketmaster has served EventFacets through both hosts. Match the event ID
    # and terminal /facets path rather than hard-coding one historical URL.
    if (
        host in {"services.ticketmaster.com", "offeradapter.ticketmaster.com"}
        and event_id in path
        and path.rstrip("/").endswith("/facets")
    ):
        return "facets"
    if host == "pubapi.ticketmaster.com" and path == f"/avsc/events/{event_id}":
        return "avsc"
    if host == "pubapi.ticketmaster.com" and path == f"/sdk/static/manifest/v1/{event_id}":
        return "manifest"
    return None


def capture_signals(driver: webdriver.Chrome, event: Event, seconds: float) -> Dict[str, Any]:
    deadline = time.time() + seconds
    requests: Dict[str, Dict[str, str]] = {}
    responses: Dict[str, Dict[str, Any]] = {}
    finished: Set[str] = set()
    processed: Set[str] = set()

    facet_bodies: List[Dict[str, Any]] = []
    facet_sources: List[str] = []
    avsc_raw: Optional[bytes] = None
    manifest_raw: Optional[bytes] = None
    errors: List[str] = []

    while time.time() < deadline:
        try:
            logs = driver.get_log("performance")
        except Exception as exc:
            logs = []
            if not any(x.startswith("PERF_LOG_ERROR:") for x in errors):
                errors.append(f"PERF_LOG_ERROR:{exc}")

        for entry in logs:
            try:
                msg = json.loads(entry["message"])["message"]
            except Exception:
                continue

            method = msg.get("method")
            p = msg.get("params", {})
            rid = p.get("requestId")
            if not rid:
                continue

            if method == "Network.requestWillBeSent":
                req = p.get("request", {})
                u = urlparse(req.get("url", ""))
                kind = classify_request(u.netloc, u.path, event.event_id)
                if kind:
                    requests[rid] = {"kind": kind, "url": req.get("url", ""), "host": u.netloc}

            elif method == "Network.responseReceived" and rid in requests:
                r = p.get("response", {})
                responses[rid] = {
                    "status": int(r.get("status", 0) or 0),
                    "mime": r.get("mimeType", ""),
                }

            elif method == "Network.loadingFinished" and rid in requests:
                finished.add(rid)

            elif method == "Network.loadingFailed" and rid in requests:
                error = p.get("errorText") or "unknown"
                errors.append(f"{requests[rid]['kind']}:NETWORK_FAILED:{error}")

        for rid in list(finished):
            if rid in processed or rid not in responses:
                continue
            processed.add(rid)

            reqinfo = requests[rid]
            kind = reqinfo["kind"]
            resp = responses[rid]

            if resp["status"] != 200:
                errors.append(f"{kind}:HTTP_{resp['status']}")
                continue

            try:
                result = driver.execute_cdp_cmd("Network.getResponseBody", {"requestId": rid})
                raw = decode_cdp_body(result)
            except Exception as exc:
                errors.append(f"{kind}:BODY_ERROR:{exc}")
                continue
            if len(raw) > MAX_CAPTURE_BODY_BYTES:
                errors.append(f"{kind}:BODY_TOO_LARGE:{len(raw)}")
                continue

            if kind == "facets":
                try:
                    data = json.loads(raw.decode("utf-8"))
                    if (
                        isinstance(data, dict)
                        and data.get("eventId") in (None, event.event_id)
                        and isinstance(data.get("facets"), list)
                    ):
                        facet_bodies.append(data)
                        facet_sources.append(reqinfo.get("url", ""))
                except Exception as exc:
                    errors.append(f"facets:JSON_ERROR:{exc}")

            elif kind == "avsc":
                avsc_raw = raw

            elif kind == "manifest":
                manifest_raw = raw

        enough_facets = len(facet_bodies) >= int(CONFIG.get("expected_facets_responses", 3))
        if enough_facets and avsc_raw is not None:
            break

        time.sleep(0.15)

    if manifest_raw is not None:
        try:
            event.manifest = json.loads(manifest_raw.decode("utf-8"))
        except Exception as exc:
            errors.append(f"manifest:JSON_ERROR:{exc}")

    if avsc_raw is None:
        avsc = {
            "status": "NO_SIGNAL",
            "activity": None,
            "available": None,
            "fingerprint": None,
            "reserved_available": None,
            "available_section_count": None,
            "available_sections": [],
            "ga_like_sections": [],
            "offer_names": [],
            "offer_metadata": [],
            "ticket_type_names": {},
        }
    else:
        try:
            avsc = parse_availability(avsc_raw, event.manifest)
        except Exception as exc:
            avsc = {
                "status": "DECODE_ERROR",
                "activity": None,
                "available": None,
                "fingerprint": None,
                "reserved_available": None,
                "available_section_count": None,
                "available_sections": [],
                "ga_like_sections": [],
                "offer_names": [],
                "offer_metadata": [],
                "ticket_type_names": {},
            }
            errors.append(f"avsc:DECODE_ERROR:{exc}")

    facets = classify_facets(facet_bodies, avsc.get("ticket_type_names") or {})
    facets["sources"] = list(dict.fromkeys(facet_sources))

    return {
        "facets": facets,
        "avsc": avsc,
        "avsc_raw": avsc_raw,
        "errors": errors,
    }


# ---------- v7.3 decision hierarchy ----------

def combine_signals(signals: Dict[str, Any]) -> Dict[str, Any]:
    facets = signals["facets"]
    avsc = signals["avsc"]

    # Facets is authoritative. AVSC can never promote a result to AVAILABLE.
    if facets.get("available") is True:
        status, available = "AVAILABLE", True
    elif facets.get("status") in {"EMPTY", "PLATINUM_ONLY", "RESALE_ONLY", "PRIMARY_UNRESOLVED", "NONSTANDARD_ONLY"}:
        status, available = facets.get("status"), False
    elif avsc.get("activity") is True:
        status, available = "AVSC_ACTIVITY", None
    else:
        status, available = "NO_SIGNAL", None

    combined_fp = hashlib.sha256(
        json.dumps(
            {
                "facets_status": facets.get("status"),
                # Alert deduplication tracks only actionable standard-primary
                # inventory. AVSC remains an early-warning/verification signal.
                "standard_inventory": facets.get("alert_fingerprint"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    return {
        "status": status,
        "available": available,
        "fingerprint": combined_fp,
        "facets": facets,
        "avsc": avsc,
        "errors": signals.get("errors", []),
        "avsc_raw": signals.get("avsc_raw"),
    }


def signal_summary(c: Dict[str, Any]) -> str:
    f = c["facets"]
    a = c["avsc"]
    parts = [
        f"FACETS={f['status']}"
        + (f" lengths={f.get('facet_lengths', [])}" if f["status"] != "NO_SIGNAL" else ""),
        f"AVSC={a['status']}",
    ]
    if a.get("activity") is not None:
        parts[-1] += f" reserved={a.get('reserved_available')} sections={a.get('available_section_count')}"
        if a.get("ga_like_sections"):
            parts[-1] += f" GA={a['ga_like_sections']}"
    if f.get("details"):
        parts.append("FACET_DETAIL=" + f["details"][0])
    return " | ".join(parts)


def avsc_material_change(event: Event, c: Dict[str, Any]) -> bool:
    """True only after a baseline exists, so startup doesn't cause a retry burst."""
    a = c.get("avsc", {})
    if a.get("activity") is not True or not a.get("fingerprint"):
        return False
    old = STATE.get(event.event_id) or {}
    old_fp = old.get("avsc_fp")
    return bool(old_fp and old_fp != a.get("fingerprint"))


def verify_after_avsc_change(driver: webdriver.Chrome, event: Event, first: Dict[str, Any]) -> Dict[str, Any]:
    """AVSC changed: briefly re-run normal page loads looking for authoritative Facets."""
    if not avsc_material_change(event, first) or first.get("available") is True:
        return first

    attempts = int(CONFIG.get("avsc_facets_verify_attempts", 3))
    delay = float(CONFIG.get("avsc_facets_verify_delay_seconds", 1.0))
    seconds = float(CONFIG.get("avsc_facets_verify_capture_seconds", 5.0))
    logging.info(
        "%s: AVSC fingerprint changed; running %d Facets verification attempt(s)",
        event.name, attempts,
    )

    best = first
    rank = {"NO_SIGNAL": 0, "AVSC_ACTIVITY": 1, "EMPTY": 2, "NONSTANDARD_ONLY": 2, "PRIMARY_UNRESOLVED": 2,
            "PLATINUM_ONLY": 2, "RESALE_ONLY": 2, "AVAILABLE": 3}
    for i in range(attempts):
        if delay > 0:
            time.sleep(delay)
        clear_perf_log(driver)
        try:
            driver.refresh()
        except TimeoutException:
            logging.warning("%s: verification refresh %d timed out", event.name, i + 1)
        except WebDriverException:
            logging.exception("%s: verification refresh %d failed", event.name, i + 1)
            break
        trial = combine_signals(capture_signals(driver, event, seconds))
        logging.info("%s: verification %d/%d -> %s", event.name, i + 1, attempts, signal_summary(trial))
        if rank.get(trial["status"], 0) >= rank.get(best["status"], 0):
            best = trial
        if trial.get("available") is True:
            break
    return best


# ---------- Gmail email alerts ----------

def email_settings() -> Dict[str, Any]:
    """Read Gmail credentials/recipients only from environment variables."""
    cfg = CONFIG.get("email_alerts", {}) or {}
    user = os.environ.get("TICKET_GMAIL_USER", "").strip()
    app_password = os.environ.get("TICKET_GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
    recipients = [x.strip() for x in os.environ.get("TICKET_ALERT_EMAIL_TO", "").split(",") if x.strip()]
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "user": user,
        "app_password": app_password,
        "recipients": recipients,
        "smtp_host": cfg.get("smtp_host", "smtp.gmail.com"),
        "smtp_port": int(cfg.get("smtp_port", 465)),
        "timeout_seconds": float(cfg.get("timeout_seconds", 20)),
        "subject_prefix": cfg.get("subject_prefix", "PHISH MSG"),
    }

def validate_email_settings(settings: Dict[str, Any]) -> None:
    missing = []
    if not settings["user"]: missing.append("TICKET_GMAIL_USER")
    if not settings["app_password"]: missing.append("TICKET_GMAIL_APP_PASSWORD")
    if not settings["recipients"]: missing.append("TICKET_ALERT_EMAIL_TO")
    if missing:
        raise RuntimeError("Email alerts are enabled but missing: " + ", ".join(missing))

def send_gmail(subject: str, body: str) -> None:
    settings = email_settings()
    if not settings["enabled"]:
        return
    validate_email_settings(settings)
    msg = EmailMessage()
    msg["From"] = settings["user"]
    msg["To"] = ", ".join(settings["recipients"])
    msg["Subject"] = subject
    msg.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(settings["smtp_host"], settings["smtp_port"], timeout=settings["timeout_seconds"], context=context) as smtp:
        smtp.login(settings["user"], settings["app_password"])
        smtp.send_message(msg)

def send_email_alert(event: Event, c: Dict[str, Any]) -> None:
    settings = email_settings()
    if not settings["enabled"]:
        return
    subject = f"{settings['subject_prefix']}: TICKETS AVAILABLE — {event.name}"
    facets = c["facets"]; avsc = c["avsc"]
    lines = [
        "PHISH TICKETS AVAILABLE", "",
        f"Event: {event.name}", f"Dates: {event.dates}",
        f"Detected: {now_iso()}", f"v7.3 state: {c['status']}", "",
        "Detection details:",
        f"  FACETS: {facets['status']}" + (f" lengths={facets.get('facet_lengths', [])}" if facets['status'] != 'NO_SIGNAL' else ''),
        f"  AVSC: {avsc['status']} (early-warning only)",
    ]
    if facets.get("sources"):
        lines.append("  Facets source: " + facets["sources"][0])
    if facets.get("details"):
        lines.append("  Standard-primary facets:")
        lines += ["    " + x for x in facets["details"][:10]]
    if avsc.get("activity") is not None:
        lines += [f"  AVSC reserved-seat positions: {avsc.get('reserved_available')}", f"  AVSC available sections: {avsc.get('available_section_count')}"]
        if avsc.get("ga_like_sections"): lines.append("  GA/PIT: " + ", ".join(avsc["ga_like_sections"]))
        if avsc.get("available_sections"): lines.append("  Sections: " + ", ".join(avsc["available_sections"][:20]))
        if avsc.get("offer_names"): lines.append("  Offers: " + ", ".join(avsc["offer_names"][:10]))
    lines += ["", "Open Ticketmaster:", event.url, "", "Availability may change quickly."]
    send_gmail(subject, "\n".join(lines))

def send_test_email() -> None:
    settings = email_settings(); validate_email_settings(settings)
    send_gmail(f"{settings['subject_prefix']}: monitor test", "\n".join(["Phish MSG monitor test email", "", f"Sent: {now_iso()}", "", "If you received this, Gmail alerts in v7.3 are configured correctly."]))

# ---------- Alerting / state ----------

def save_positive_capture(event: Event, c: Dict[str, Any]) -> List[str]:
    outdir = configured_path("positive_capture_dir", "positive_captures")
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(monitor_timezone()).strftime("%Y%m%d_%H%M%S")
    saved: List[str] = []

    for i, body in enumerate(c["facets"].get("positive_bodies", []), 1):
        p = outdir / f"{safe_name(event.name)}_{stamp}_facets_{i}.json"
        p.write_text(json.dumps(body, indent=2), encoding="utf-8")
        saved.append(str(p))

    raw = c.get("avsc_raw")
    if c.get("available") is True and raw:
        p = outdir / f"{safe_name(event.name)}_{stamp}_availability.bin"
        p.write_bytes(raw)
        saved.append(str(p))

    return saved


def notify(event: Event, c: Dict[str, Any], *, visual: bool = True) -> Dict[str, Any]:
    title = f"Phish MSG tickets — {event.name}"
    msg = signal_summary(c)
    email_enabled = bool((CONFIG.get("email_alerts", {}) or {}).get("enabled", True))
    delivery: Dict[str, Any] = {"email_enabled": email_enabled, "email_delivered": None}

    logging.warning("ALERT %s: %s", event.name, msg)

    if visual:
        try:
            saved = save_positive_capture(event, c)
            if saved:
                logging.warning("%s: positive capture(s): %s", event.name, ", ".join(saved))
        except Exception:
            logging.exception("%s: positive capture failed", event.name)

    if visual and platform.system() == "Darwin" and CONFIG.get("macos_notification", True):
        try:
            safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
            safe_msg = msg.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.run(
                ["osascript", "-e", f'display notification "{safe_msg}" with title "{safe_title}"'],
                check=False,
            )
            if CONFIG.get("sound", True):
                subprocess.run(["afplay", "/System/Library/Sounds/Glass.aiff"], check=False)
        except Exception:
            logging.exception("%s: macOS notification failed", event.name)

    if email_enabled:
        try:
            send_email_alert(event, c)
            logging.warning("%s: Gmail alert sent", event.name)
            delivery["email_delivered"] = True
        except Exception:
            logging.exception("%s: Gmail alert failed", event.name)
            delivery["email_delivered"] = False

    if visual and CONFIG.get("open_browser_on_alert", True):
        try:
            webbrowser.open(event.url, new=2)
        except Exception:
            logging.exception("%s: browser open failed", event.name)
    return delivery


def parse_last_alert(old: Dict[str, Any]) -> Optional[datetime]:
    value = old.get("last_alert")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=monitor_timezone()) if parsed.tzinfo is None else parsed
    except Exception:
        return None


def should_alert(old: Optional[Dict[str, Any]], c: Dict[str, Any]) -> bool:
    if c["available"] is not True:
        return False

    if not old or old.get("available") is not True:
        return True

    if old.get("fingerprint") != c.get("fingerprint"):
        return True

    email_enabled = bool((CONFIG.get("email_alerts", {}) or {}).get("enabled", True))
    if email_enabled and old.get("email_delivered") is not True:
        prev = parse_last_alert(old)
        retry_seconds = float(CONFIG.get("email_retry_seconds", 60))
        return prev is None or (datetime.now(monitor_timezone()) - prev >= timedelta(seconds=retry_seconds))

    repeat = float(CONFIG.get("repeat_positive_alert_minutes", 10))
    prev = parse_last_alert(old)
    return prev is None or (datetime.now(monitor_timezone()) - prev >= timedelta(minutes=repeat))


def process(event: Event, c: Dict[str, Any]) -> None:
    old = STATE.get(event.event_id)

    if c["status"] in {"NO_SIGNAL", "AVSC_ACTIVITY"}:
        logging.warning("%s: %s | %s", event.name, c["status"], signal_summary(c))
    else:
        logging.info("%s: %s => %s", event.name, signal_summary(c), c["status"])
    if c["errors"]:
        logging.warning("%s: diagnostics: %s", event.name, "; ".join(c["errors"][:3]))

    email_enabled = bool((CONFIG.get("email_alerts", {}) or {}).get("enabled", True))
    same_positive = bool(
        old
        and old.get("available") is True
        and old.get("fingerprint") == c.get("fingerprint")
    )
    email_retry_only = bool(
        same_positive and email_enabled and old.get("email_delivered") is not True
    )
    do_alert = should_alert(old, c)
    delivery: Dict[str, Any] = {}
    if do_alert:
        delivery = notify(event, c, visual=not email_retry_only)

    record = {
        "available": c["available"],
        "status": c["status"],
        "fingerprint": c["fingerprint"],
        "facets_status": c["facets"]["status"],
        "facets_fp": c["facets"].get("fingerprint"),
        "avsc_status": c["avsc"]["status"],
        "avsc_fp": c["avsc"].get("fingerprint"),
        "last_seen": now_iso(),
    }
    if do_alert:
        record["last_alert"] = now_iso()
    elif old and old.get("last_alert"):
        record["last_alert"] = old["last_alert"]
    if c["available"] is True:
        if "email_delivered" in delivery:
            record["email_delivered"] = delivery["email_delivered"]
        elif same_positive and old:
            record["email_delivered"] = old.get("email_delivered")

    STATE[event.event_id] = record
    save_json(configured_path("state_file", "state_v7_2.json"), STATE)

    history_path = configured_path("history_file", "history_v7_2.jsonl")
    history_path.parent.mkdir(parents=True, exist_ok=True)
    append_jsonl(history_path, {
        "timestamp": now_iso(),
        "event": event.name,
        "event_id": event.event_id,
        "status": c["status"],
        "facets_status": c["facets"]["status"],
        "facet_lengths": c["facets"].get("facet_lengths", []),
        "facet_sources": c["facets"].get("sources", []),
        "facet_details": c["facets"].get("details", [])[:5],
        "avsc_status": c["avsc"]["status"],
        "avsc_reserved": c["avsc"].get("reserved_available"),
        "avsc_sections": c["avsc"].get("available_section_count"),
        "avsc_ga": c["avsc"].get("ga_like_sections", []),
        "alerted": do_alert,
        "email_delivered": record.get("email_delivered"),
        "errors": c["errors"][:5],
    })


# ---------- Poll loop ----------

def open_event(driver: webdriver.Chrome, event: Event, first: bool) -> bool:
    if first:
        event.handle = driver.current_window_handle
    else:
        driver.switch_to.new_window("tab")
        event.handle = driver.current_window_handle

    clear_perf_log(driver)
    try:
        driver.get(event.url)
    except TimeoutException:
        logging.warning("%s: initial load timeout; continuing", event.name)

    signals = capture_signals(
        driver, event, float(CONFIG.get("initial_capture_seconds", 10))
    )
    combined = combine_signals(signals)
    process(event, combined)
    return bool(combined["errors"] or combined["status"] == "NO_SIGNAL")


def refresh_event(driver: webdriver.Chrome, event: Event) -> bool:
    switch(driver, event)
    clear_perf_log(driver)

    try:
        driver.refresh()
    except TimeoutException:
        logging.warning("%s: refresh timeout; inspecting traffic anyway", event.name)
    except WebDriverException:
        logging.exception("%s: Chrome refresh failed", event.name)
        return True

    signals = capture_signals(
        driver, event, float(CONFIG.get("capture_seconds_after_refresh", 8))
    )
    combined = combine_signals(signals)
    combined = verify_after_avsc_change(driver, event, combined)
    process(event, combined)
    return bool(combined["errors"] or combined["status"] == "NO_SIGNAL")


def round_delay(consecutive_error_rounds: int = 0) -> float:
    normal = float(CONFIG.get("normal_round_seconds", 30))
    fast = CONFIG.get("fast_round_seconds")
    window = CONFIG.get("fast_poll_window")
    local_now = datetime.now(monitor_timezone())
    if fast is not None and window:
        hhmm = local_now.strftime("%H:%M")
        start, end = str(window["start"]), str(window["end"])
        in_window = start <= hhmm <= end if start <= end else hhmm >= start or hhmm <= end
        if in_window:
            normal = float(fast)

    cap: Optional[float] = None
    if consecutive_error_rounds:
        multiplier = 2 ** min(consecutive_error_rounds, 8)
        cap = float(CONFIG.get("max_error_backoff_seconds", 3600))
        normal = min(normal * multiplier, cap)

    jitter = min(max(float(CONFIG.get("poll_jitter_fraction", 0.1)), 0.0), 0.5)
    delay = max(1.0, normal * random.uniform(1.0 - jitter, 1.0 + jitter))
    return min(delay, cap) if cap is not None else delay


def main() -> None:
    global CONFIG, STATE

    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--test-email", action="store_true", help="Send one Gmail test message and exit.")
    args = ap.parse_args()

    CONFIG = load_json(Path(args.config), None)
    if not CONFIG:
        raise SystemExit("Missing config.json")

    log_path = configured_path("log_file", "tracker_v7_2.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_path, encoding="utf-8"),
        ],
    )

    if args.test_email:
        try:
            send_test_email()
            logging.info("Gmail test email sent successfully.")
            return
        except Exception:
            logging.exception("Gmail test email failed.")
            raise SystemExit(2)

    if CONFIG.get("email_alerts", {}).get("enabled", True):
        try:
            s = email_settings(); validate_email_settings(s)
            logging.info("Gmail alerts configured for %d recipient(s).", len(s["recipients"]))
        except Exception as exc:
            logging.warning("Gmail alerts not configured: %s", exc)

    events = build_events(CONFIG)
    loaded_state = load_json(configured_path("state_file", "state_v7_2.json"), {})
    if not isinstance(loaded_state, dict):
        logging.warning("State file must contain a JSON object; starting with empty state.")
        loaded_state = {}
    STATE = loaded_state

    driver = create_driver(CONFIG)
    try:
        consecutive_error_rounds = 0
        startup_error = False
        for i, event in enumerate(events):
            try:
                startup_error = open_event(driver, event, first=(i == 0)) or startup_error
            except Exception:
                logging.exception("%s: initial event load failed", event.name)
                startup_error = True
            if i < len(events) - 1:
                time.sleep(float(CONFIG.get("between_events_delay_seconds", 2)))

        logging.info("Ready. Monitoring %d MSG event(s) with v7.3 facets-authoritative detection.", len(events))
        if startup_error:
            consecutive_error_rounds = 1

        while True:
            round_had_error = False
            for event in events:
                try:
                    round_had_error = refresh_event(driver, event) or round_had_error
                except Exception:
                    logging.exception("%s: unexpected polling error", event.name)
                    round_had_error = True
                time.sleep(float(CONFIG.get("between_events_delay_seconds", 2)))

            consecutive_error_rounds = consecutive_error_rounds + 1 if round_had_error else 0
            delay = round_delay(consecutive_error_rounds)
            logging.info("Next round in %.1f seconds (error streak %d)", delay, consecutive_error_rounds)
            time.sleep(delay)

    except KeyboardInterrupt:
        logging.info("Stopped.")
    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    main()
