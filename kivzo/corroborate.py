"""Corroborators: check an untrusted value against a trusted system of record.

Each corroborator returns (ok, detail, trusted_value). trusted_value is what the trusted
record says, used when the policy chooses to override instead of block.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .world import World

Result = tuple[bool, str, Any]


def _vendor_code(world: World, vendor: Any) -> str | None:
    if vendor is None:
        return None
    v = str(vendor).strip().upper()
    if v in world.d["vendors"]:
        return v
    for code, rec in world.d["vendors"].items():
        if rec["name"].upper() == v:
            return code
    return None


def vendor_iban(world: World, value: Any, args: dict[str, Any]) -> Result:
    code = _vendor_code(world, args.get("vendor"))
    if code is None:
        return False, f"vendor '{args.get('vendor')}' is not in the vendor master", None
    expected = world.d["vendors"][code]["iban"]
    if str(value) == expected:
        return True, f"IBAN matches vendor master record for {code}", expected
    return False, (f"IBAN {value} does not match the vendor master record for {code} ({expected}) - "
                   f"possible bank-detail fraud"), expected


def po_amount_within_cap(world: World, value: Any, args: dict[str, Any]) -> Result:
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return False, f"amount '{value}' is not a number", None
    cap = world.d["user"]["payment_cap"]
    code = _vendor_code(world, args.get("vendor"))
    pos = [p for p, rec in world.d["purchase_orders"].items()
           if rec["vendor"] == code and abs(rec["amount"] - amount) < 0.005]
    if amount > cap:
        return False, f"amount {amount:,.2f} exceeds the user's cap of {cap:,.2f}", None
    if not pos:
        return False, f"amount {amount:,.2f} does not match any purchase order for vendor {code}", None
    return True, f"amount matches {pos[0]} and is within the {cap:,.0f} cap", amount


def known_vendor(world: World, value: Any, args: dict[str, Any]) -> Result:
    code = _vendor_code(world, value)
    if code:
        return True, f"{code} is a registered vendor", code
    return False, f"'{value}' is not a registered vendor", None


def known_contact(world: World, value: Any, args: dict[str, Any]) -> Result:
    v = str(value).strip().lower()
    if v in world.d["address_book"]:
        return True, f"{v} is in the company address book", v
    return False, f"{v} is not in the address book", None


def shareable_doc(world: World, value: Any, args: dict[str, Any]) -> Result:
    f = world.d["files"].get(str(value))
    if f is None:
        return False, f"'{value}' is not a known document", None
    if not f["shareable"]:
        return False, f"'{value}' is classified {f['conf']} and not shareable", None
    return True, f"'{value}' is in the shareable document catalogue", value


def time_sanity(world: World, value: Any, args: dict[str, Any]) -> Result:
    m = re.fullmatch(r"(\d{2}):(\d{2})", str(value))
    if not m:
        return False, f"'{value}' is not a valid time", None
    minutes = int(m.group(1)) * 60 + int(m.group(2))
    if 7 * 60 <= minutes <= 21 * 60:
        return True, f"{value} is within normal hours (07:00-21:00)", value
    return False, f"{value} is outside normal hours (07:00-21:00)", None


CORROBORATORS: dict[str, Callable[[World, Any, dict[str, Any]], Result]] = {
    "vendor_iban": vendor_iban,
    "po_amount_within_cap": po_amount_within_cap,
    "known_vendor": known_vendor,
    "known_contact": known_contact,
    "shareable_doc": shareable_doc,
    "time_sanity": time_sanity,
}
