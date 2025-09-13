#!/usr/bin/env python3
import json, sys, os, csv, re, binascii
from typing import Any, Dict, List, Optional

TARGETS = {
    "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex",
    "EVP_EncryptUpdate", "EVP_DecryptUpdate",
    "EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex",
}

ADDR_RE = re.compile(r"^\s*[0-9a-fA-F]{6,}\s")
HEX_RE  = re.compile(r"\b[0-9a-fA-F]{2}\b")

def load_events(input_path: str) -> List[Dict[str, Any]]:
    stem = os.path.splitext(os.path.basename(input_path))[0]
    ndj = f"{stem}__events.ndjson"
    if os.path.exists(ndj):
        out: List[Dict[str, Any]] = []
        with open(ndj, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try: out.append(json.loads(line))
                    except json.JSONDecodeError: pass
        return out
    with open(input_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    return d.get("dynamic_analysis", {}).get("raw_captures", [])

def get_ptr(args: List[Dict[str, Any]], idx: int) -> Optional[str]:
    if 0 <= idx < len(args):
        v = args[idx].get("value")
        if v is not None:
            return str(v)
    return None

def parse_hexdump_to_bytes(s: str, limit: Optional[int] = None) -> bytes:
    """Parse common hexdump format (addr + 16 bytes + ASCII) to raw bytes."""
    if not s: return b""
    out = bytearray()
    for line in s.splitlines():
        if not ADDR_RE.match(line):
            continue
        toks = HEX_RE.findall(line)
        # keep only first 16 byte tokens from this line
        if len(toks) > 16: toks = toks[:16]
        for t in toks:
            out.append(int(t, 16))
            if limit is not None and len(out) >= limit:
                return bytes(out)
    return bytes(out)

def ratio_printable(b: bytes) -> float:
    if not b: return 0.0
    cnt = sum(1 for x in b if 32 <= x <= 126)
    return cnt / len(b)

def looks_like_text_or_rodata(b: bytes) -> bool:
    if not b: return True
    # 너무 많은 ASCII, 혹은 긴 반복/패턴은 텍스트/상수 가능성 ↑
    if ratio_printable(b) >= 0.75:  # 문자열/심볼/영문이 많은 경우
        return True
    # all-zero 혹은 매우 편향된 값
    unique = set(b)
    if len(unique) <= 2:  # 거의 0x00/0xFF 등
        return True
    return False

def first_n_hex(b: bytes, n: int) -> str:
    if not b: return ""
    return binascii.hexlify(b[:n]).decode()

def read_mem_hex(obj: Dict[str, Any], *path: str) -> str:
    cur = obj
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return ""
        cur = cur[k]
    return cur or ""

def hexdump_from_arg(args: List[Dict[str, Any]], index: int) -> str:
    if index < 0 or index >= len(args):
        return ""
    return read_mem_hex(args[index], "memory", "hex")

def post_hexdump_from_arg(args: List[Dict[str, Any]], index: int) -> str:
    if 0 <= index < len(args):
        return read_mem_hex(args[index], "post", "memory", "hex")
    return ""

def to_str(x): return "" if x is None else str(x)

def extract(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for i, r in enumerate(events):
        fn = r.get("functionName") or r.get("name") or ""
        if fn not in TARGETS:
            continue

        args = r.get("args") or []
        dec  = r.get("decoded") or {}

        row: Dict[str, Any] = {
            "idx": i,
            "api": (dec.get("api") or fn),
            "functionName": fn,

            # pointers (항상 채움)
            "ctx_ptr": get_ptr(args, 0) or "",
            "key_ptr": get_ptr(args, 3) or "",
            "iv_ptr":  get_ptr(args, 4) or "",
            "out_ptr": get_ptr(args, 1) or "",
            "in_ptr":  get_ptr(args, 3) or "",

            # lengths
            "key_len": to_str(dec.get("key_iv", {}).get("key_len")),
            "iv_len":  to_str(dec.get("key_iv", {}).get("iv_len")),
            "in_len":  to_str(dec.get("in_len")),
            "out_len": to_str(dec.get("out_len")),

            # raw hexdump(text형) 그대로 (호환성 유지)
            "key_hexdump": "",
            "iv_hexdump": "",
            "in_hexdump": "",
            "out_hexdump": "",

            # byte 파싱된 간결 버전(앞부분만)
            "key_hex": "",
            "iv_hex": "",
            "in_hex": "",
            "out_hex": "",

            # 품질/사유
            "key_quality": "",
            "iv_quality": "",
            "in_quality": "",
            "out_quality": "",
        }

        # ---- decoded 우선 ----
        if isinstance(dec, dict):
            ki = dec.get("key_iv") or {}
            if ki.get("key_sample"): row["key_hexdump"] = ki["key_sample"]
            if ki.get("iv_sample"):  row["iv_hexdump"]  = ki["iv_sample"]
            if dec.get("in_sample"):  row["in_hexdump"]  = dec["in_sample"]
            if dec.get("out_sample"): row["out_hexdump"] = dec["out_sample"]

        # ---- signature 기반 보완 ----
        if not row["key_hexdump"] or not row["iv_hexdump"]:
            if fn in ("EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex"):
                row["key_hexdump"] = row["key_hexdump"] or hexdump_from_arg(args, 3)
                row["iv_hexdump"]  = row["iv_hexdump"]  or hexdump_from_arg(args, 4)

        if not row["in_hexdump"]:
            if fn in ("EVP_EncryptUpdate", "EVP_DecryptUpdate"):
                row["in_hexdump"] = hexdump_from_arg(args, 3)
                # 길이 추정(inl 스칼라)
                try:
                    inl = args[4].get("value")
                    row["in_len"] = to_str(inl)
                except Exception:
                    pass

        if not row["out_hexdump"]:
            # returnValue.memory.hex 또는 post-snapshot(out 버퍼)이 있으면 사용
            rv_hex = read_mem_hex(r, "returnValue", "memory", "hex")
            post_hex = post_hexdump_from_arg(args, 1)
            row["out_hexdump"] = rv_hex or post_hex

        # ---- hexdump -> bytes 파싱 & 필터링/트리밍 ----
        # in_len 정수 해석 (0x.. 허용)
        def to_int_len(s: str) -> Optional[int]:
            if not s: return None
            try:
                return int(s, 0)
            except Exception:
                return None

        in_len = to_int_len(row["in_len"])
        # key/iv는 일반적으로 16/24/32를 자주 쓰니 32/16으로 표본화
        key_b = parse_hexdump_to_bytes(row["key_hexdump"], limit=64)  # 최대 64만
        iv_b  = parse_hexdump_to_bytes(row["iv_hexdump"],  limit=32)
        in_b  = parse_hexdump_to_bytes(row["in_hexdump"],  limit=in_len if in_len else 64)
        out_b = parse_hexdump_to_bytes(row["out_hexdump"], limit=64)

        # 품질 판정 및 채우기
        if key_b:
            if looks_like_text_or_rodata(key_b):
                row["key_quality"] = "filtered:text/rodata/constant-looking"
            else:
                row["key_hex"] = first_n_hex(key_b, 32)  # AES-256까지 커버
                row["key_quality"] = "ok"
                if not row["key_len"]:
                    # 길이 추정(보이는 바이트 기준)
                    row["key_len"] = str(32 if len(key_b) >= 32 else (24 if len(key_b) >= 24 else (16 if len(key_b) >= 16 else len(key_b))))
        if iv_b:
            if looks_like_text_or_rodata(iv_b):
                row["iv_quality"] = "filtered:text/rodata/constant-looking"
            else:
                row["iv_hex"] = first_n_hex(iv_b, 16)
                row["iv_quality"] = "ok"
                if not row["iv_len"]:
                    row["iv_len"] = str(16 if len(iv_b) >= 16 else len(iv_b))

        if in_b:
            row["in_hex"] = binascii.hexlify(in_b).decode()
            row["in_quality"] = "ok"
        elif row["in_hexdump"]:
            row["in_quality"] = "empty-after-parse"

        if out_b:
            row["out_hex"] = binascii.hexlify(out_b).decode()
            row["out_quality"] = "ok"
        elif row["out_hexdump"]:
            row["out_quality"] = "empty-after-parse"

        rows.append(row)
    return rows

def write_json(path: str, rows: List[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

def write_csv(path: str, rows: List[Dict[str, Any]]):
    cols = [
        "idx","api","functionName",
        "ctx_ptr","key_ptr","iv_ptr","in_ptr","out_ptr",
        "key_len","iv_len","in_len","out_len",
        "key_hex","iv_hex","in_hex","out_hex",
        "key_quality","iv_quality","in_quality","out_quality",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c,"") for c in cols])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} <analysis_result_*.json>", file=sys.stderr)
        sys.exit(1)
    input_path = sys.argv[1]
    events = load_events(input_path)
    rows = extract(events)
    stem = os.path.splitext(os.path.basename(input_path))[0]
    out_json = f"{stem}__evp.json"
    out_csv  = f"{stem}__evp.csv"
    write_json(out_json, rows)
    write_csv(out_csv, rows)
    print(f"[ok] extracted {len(rows)} EVP records -> {out_json} (+ {out_csv})")

if __name__ == "__main__":
    main()
