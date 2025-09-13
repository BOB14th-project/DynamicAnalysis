#!/usr/bin/env python3
import json, sys, os
from typing import Any, Dict, Iterable, Optional

def get(obj: Dict[str, Any], *keys, default=None):
    cur = obj
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def fmt_hexdump(s: Optional[str]) -> str:
    # 에이전트가 준 hexdump 문자열(주소/ASCII 포함)을 그대로 씀
    return s or ""

def render_event(rec: Dict[str, Any]) -> str:
    mod = rec.get("moduleName") or rec.get("module") or "unknown"
    fn  = rec.get("functionName") or rec.get("name") or rec.get("symbol") or "unknown"
    out = []
    out.append(f"=== {mod}!{fn} ===")
    args = rec.get("args")
    if isinstance(args, list) and args:
        out.append("ARGS:")
        for a in args:
            idx  = a.get("index")
            kind = a.get("kind","scalar")
            val  = a.get("value","0")
            out.append(f"  arg{idx} [{kind}] = {val}")
            hex_s = get(a, "memory", "hex")
            if hex_s:
                out.append("                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF")
                out.append(fmt_hexdump(hex_s))
    # decoded(있으면)도 덧붙임
    if "decoded" in rec and isinstance(rec["decoded"], dict):
        d = rec["decoded"]
        out.append("DECODED:")
        api = d.get("api")
        if api: out.append(f"  api = {api}")
        evp = d.get("evp_ctx")
        if evp:
            out.append(f"  cipher={evp.get('cipher_name')} blk={evp.get('block_size')} key_len={evp.get('key_len')} iv_len={evp.get('iv_len')} enc={evp.get('encrypting')}")
        ki = d.get("key_iv")
        if ki:
            out.append(f"  key_len={ki.get('key_len')} iv_len={ki.get('iv_len')}")
            if ki.get("key_sample"): out.append("  KEY SAMPLE:\n" + fmt_hexdump(ki["key_sample"]))
            if ki.get("iv_sample"):  out.append("  IV SAMPLE:\n"  + fmt_hexdump(ki["iv_sample"]))
        if d.get("in_sample"):  out.append("  IN SAMPLE:\n"  + fmt_hexdump(d["in_sample"]))
        if d.get("out_sample"): out.append("  OUT SAMPLE:\n" + fmt_hexdump(d["out_sample"]))
        if "in_len"  in d: out.append(f"  in_len={d['in_len']}")
        if "out_len" in d: out.append(f"  out_len={d['out_len']}")
        if "ret"     in d: out.append(f"  ret={d['ret']}")
    # 반환값
    rv = rec.get("returnValue")
    if isinstance(rv, dict):
        kind = rv.get("kind","scalar")
        val  = rv.get("value","0")
        out.append(f"RET [{kind}] = {val}")
        hex_s = get(rv, "memory", "hex")
        if hex_s:
            out.append("                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF")
            out.append(fmt_hexdump(hex_s))
    return "\n".join(out) + "\n"

def write_text(path: str, lines: Iterable[str]):
    with open(path, "w", encoding="utf-8") as f:
        for s in lines:
            f.write(s)

def write_ndjson(path: str, recs: Iterable[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} <analysis_result_*.json>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = data.get("dynamic_analysis", {}).get("raw_captures", [])
    stem = os.path.splitext(os.path.basename(input_path))[0]
    out_txt = f"{stem}__params.txt"
    out_ndj = f"{stem}__events.ndjson"

    # 보기 좋은 txt
    write_text(out_txt, (render_event(r) for r in events))
    # 사이드카 NDJSON(추출 파이프라인용)
    write_ndjson(out_ndj, events)

    print(f"[ok] wrote: {out_txt}")
    print(f"[ok] wrote: {out_ndj}")

if __name__ == "__main__":
    main()
