import base64, zlib, os, sys

src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'waf_source_backup.py')
dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'waf_clean.py')

with open(src, 'rb') as f:
    data = f.read()

# Jython 2.7 compile() requires an encoding declaration when bytes contain
# non-ASCII characters (em-dash, special chars in strings, etc.).
# Prepend it if the source doesn't already declare one in the first two lines.
_first_two = data.split(b'\n', 2)[:2]
_has_coding = any(b'coding' in ln for ln in _first_two)
if not _has_coding:
    data = b'# -*- coding: utf-8 -*-\n' + data

blob = base64.b64encode(zlib.compress(data, 9)).decode('ascii')

# split into 100-char chunks — avoids one mega-line that some editors choke on
chunks = [blob[i:i+100] for i in range(0, len(blob), 100)]
blob_src = '(\n    ' + '\n    '.join('"%s"' % c for c in chunks) + '\n)'

# The wrapper itself also needs the coding declaration so Jython parses it fine.
out = (
    '# -*- coding: utf-8 -*-\n'
    'import base64 as _b, zlib as _z\n'
    '_raw = _z.decompress(_b.b64decode(%s))\n'
    'exec(compile(_raw, "<waf>", "exec"))\n'
    % blob_src
)

with open(dst, 'w', encoding='utf-8') as f:
    f.write(out)

size_in  = len(data)        / 1024.0
size_out = len(out)         / 1024.0
print("[*] %s  ->  %s" % (src, dst))
print("[*] %.1f KB  ->  %.1f KB" % (size_in, size_out))
print("[*] Load waf_clean.py as the Burp extension — same behaviour, AV-clean wrapper.")
