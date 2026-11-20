"""Regenerate src/assets/icons/preview.html: the icon set with its story, and every icon at 16/20px on paper and
on the dark rail (icon-set-generator QA)."""
import json, re, pathlib
root = pathlib.Path(__file__).resolve().parent.parent / "src/assets"
strip = lambda s: re.sub(r'<!--.*?-->', '', s, flags=re.S)
spec = json.loads((root / "icons/style-spec.json").read_text())
icon = lambda n, px=None: (root / f"icons/{n}.svg").read_text().replace('width="24" height="24"', f'width="{px}" height="{px}"') if px else (root / f"icons/{n}.svg").read_text()
cells = "".join(f'<figure><div class="ic">{icon(n)}</div><figcaption><b>{n}</b><span>{d}</span></figcaption></figure>' for n, d in spec["icons"].items())
html = f'''<!doctype html><html><head><meta charset="utf-8"><title>ForenSight symbols</title><style>
body{{margin:0;background:#F3F0E9;color:#1C1B18;font:14px/1.45 system-ui,sans-serif;padding:32px 40px}}
h1{{font:500 30px Georgia,serif;margin:0 0 4px}} h2{{font:500 20px Georgia,serif;margin:32px 0 12px}} p{{color:#5F594E;max-width:72ch;margin:0}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}} figure{{margin:0;background:#FBFAF6;border:1px solid #D9D3C5;border-radius:6px;padding:16px;display:flex;gap:14px;align-items:flex-start}}
.ic svg{{width:32px;height:32px}} figcaption{{display:flex;flex-direction:column;font-size:12.5px}} figcaption span{{color:#5F594E}}
.concepts{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}} .concept{{flex-direction:column;align-items:center}} .big svg{{width:150px;height:150px}}
.strip{{display:flex;gap:36px;align-items:flex-end;padding:20px;border-radius:6px}} .sz{{display:flex;flex-direction:column;align-items:center;gap:6px}} .sz svg{{display:block}}
.paper{{background:#FBFAF6;border:1px solid #D9D3C5}} .rail{{background:#1E211F;color:#ECE8DE}} .rail small{{color:#ACA596}}
.sizes{{display:flex;gap:10px;align-items:center;margin-top:10px}} .sizes svg{{display:block}}
</style></head><body>
<h1>ForenSight symbols</h1><p>Every symbol is an object from the investigator's evidence room. Built to one spec: 24px grid, 1.5 stroke, round caps and joins, 2px padding, currentColor only.</p>
<h2>Icon set</h2><div class="grid">{cells}</div>
<h2>Icons at 16px and 20px</h2><div class="strip paper"><div class="sizes">{"".join(icon(n, 16) for n in spec["icons"])}</div></div><div class="strip paper" style="margin-top:8px"><div class="sizes">{"".join(icon(n, 20) for n in spec["icons"])}</div></div><div class="strip rail" style="margin-top:8px"><div class="sizes">{"".join(icon(n, 20) for n in spec["icons"])}</div></div>
</body></html>'''
(root / "icons/preview.html").write_text(html)
print("wrote", root / "icons/preview.html")
