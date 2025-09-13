# filter_trace.py
import re, json, sys, itertools
from pathlib import Path
INCLUDE = re.compile(r'^(EVP_|RSA_|EC_|ED25519|X25519|BN_|DH_|DSA_|HMAC_|CMAC_|AES_|ChaCha20|Poly1305|RAND_|SSL_|TLS_|SHA(1|224|256|384|512)$|MD(4|5)$|HKDF|PBKDF2)')
EXCLUDE = re.compile(r'^(CRYPTO_(malloc|zalloc|realloc|free)$|OPENSSL_(malloc|free)$|mem(cpy|set|move|cmp)$|bzero$|str.*)')
WINDOW = 50  # 앞뒤 문맥

def interesting(ev):
    fn = ev.get('payload', {}).get('functionName', '')
    if EXCLUDE.search(fn): return False
    if INCLUDE.search(fn): return True
    # 사이즈/포인터 메모리 힌트로 추가 선별 (키/IV/nonce 사이즈)
    for arg in ev.get('payload', {}).get('args', []):
        v = arg.get('value', '')
        try:
            n = int(v, 16)
            if n in (16, 24, 32, 12):  # AES 키(16/24/32), GCM IV(12)
                return True
        except: pass
        mem = arg.get('memory', {}) or {}
        hx = (mem.get('hex') or '')
        if '-----BEGIN' in hx or ' 30 82 ' in hx:  # PEM/DER 서두
            return True
    return False

def load_events(path):
    root = json.loads(Path(path).read_text(encoding='utf-8'))
    return [e for e in root.get('dynamic_analysis', {}).get('raw_captures', [])
            if e.get('type') == 'function_call']

def main(path):
    events = load_events(path)
    idx_hit = [i for i, ev in enumerate(events) if interesting(ev)]
    keep = set()
    for i in idx_hit:
        lo, hi = max(0, i-WINDOW), min(len(events), i+WINDOW+1)
        keep.update(range(lo, hi))
    filtered = [events[i] for i in sorted(keep)]

    # 함수별 카운트
    from collections import Counter
    c = Counter(ev.get('payload', {}).get('functionName','unknown') for ev in filtered)
    top = c.most_common()

    # 저장
    base = Path(path).with_suffix('')
    outj = f"{base}_filtered.json"
    outc = f"{base}_top.csv"
    with open(outj, 'w', encoding='utf-8') as f:
        json.dump({'filtered_events': filtered}, f, indent=2, ensure_ascii=False)
    with open(outc, 'w', encoding='utf-8') as f:
        f.write("count,function\n")
        for k,v in top:
            f.write(f"{v},{k}\n")

    print(f"[✓] kept {len(filtered)} / {len(events)} events")
    print(f"[✓] wrote {outj}, {outc}")

if __name__ == "__main__":
    main(sys.argv[1])
