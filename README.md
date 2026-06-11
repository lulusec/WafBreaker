# WAFko — poznámky

## Súbory

| Súbor | Popis |
|---|---|
| `waf_source_backup.py` | **Zdrojový kód — edituj toto** |
| `waf.py` | AV-čistý wrapper pre Burp — **negeneruj ručne** |
| `build.py` | Prebuilduje `waf.py` z `waf_source_backup.py` |

---

## Úprava kódu

1. Otvor `waf_source_backup.py` a zmeň čo potrebuješ
2. **Žiadne non-ASCII znaky** v log správach (`--` nie `—`, `->` nie `→`)
3. Spusti build:

```bash
python build.py
copy waf_clean.py waf.py
```

---

## Nahranie do Burp

1. Burp Suite → **Extender → Extensions → Add**
2. Extension type: **Python**
3. Extension file: vyber `waf.py`
4. Klikni **Next** — malo by sa zobraziť `[*] WafBreaker v1.0 ready.`

Po každej zmene kódu:
- Spusti build (vyššie)
- V Burpe klikni na WafBreaker → **Reload**

---

## Spustenie skenu

1. V Burpe zachyť request (Proxy / Repeater / Target)
2. Pravý klik → **Extensions → WafBreaker → Scan ...**  
   (LFI / SQLi / XSS / CMDi / SSRF)
3. Výsledky: **Extensions → WafBreaker → Output**
4. Nájdené zraniteľnosti: **Target → Issues**

---

## LFI transforms (aktuálne: 51)

Pridanie nového transformu do `waf_source_backup.py`:

```python
def lfi_moj_transform(path):
    return path.replace('/', '%NIECO')

# pridaj do LFI_TAMPERS:
("moj-transform", lfi_moj_transform, "popis"),
```

---

## GitHub

```bash
git init
git add waf_source_backup.py build.py notes.md
git commit -m "WafBreaker initial"
git remote add origin https://github.com/TY/WAFko.git
git push -u origin main
```

> `waf.py` a `waf_clean.py` daj do `.gitignore` — sú generované.

`.gitignore`:
```
waf.py
waf_clean.py
*.pyc
output.txt
```
