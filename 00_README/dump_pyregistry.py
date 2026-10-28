import sys, json
from Registry import Registry

src, out = sys.argv[1], sys.argv[2]
reg = Registry.Registry(src)
rows = []

def walk(key):
    try:
        ts = key.timestamp().isoformat()
    except Exception:
        ts = None
    values = []
    try:
        for v in key.values():
            try:
                val = v.value()
                if isinstance(val, bytes):
                    val = val.hex()
                else:
                    val = str(val)
            except Exception as e:
                val = f'ERROR:{e}'
            values.append({'name': v.name(), 'value': val, 'type': str(v.value_type())})
    except Exception as e:
        values.append({'name': '__ERROR__', 'value': str(e), 'type': ''})
    rows.append({'key_path': key.path(), 'timestamp': ts, 'values': values})
    try:
        for sk in key.subkeys():
            walk(sk)
    except Exception as e:
        rows.append({'key_path': key.path(), 'timestamp': ts,
                     'values': [{'name': '__SUBKEY_ERROR__', 'value': str(e), 'type': ''}]})

walk(reg.root())
with open(out, 'w', encoding='utf-8') as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)
print(f'Wrote {len(rows)} key records to {out}')

