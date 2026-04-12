# wappalyzerjs

Browser-based technology detection engine. Detects technologies via JS globals, DOM inspection, and script `src` analysis at runtime — the checks that HTTP-level fingerprinting cannot perform.

~4900 technologies from the [Wappalyzer](https://github.com/enthec/webappanalyzer) database, plus curated rules.

## Install

### Python (for Playwright integration)

```bash
pip install git+https://github.com/assakafpix/wappalyzerjs.git#subdirectory=python
```

### Node.js

```bash
npm install wappalyzerjs
```

## Usage

### Python + Playwright

```python
from wappalyzerjs import detect

# After navigating to a page:
results = await detect(page)
for tech in results:
    print(f"{tech['name']} v{tech['version']}")
```

Or load the script manually:

```python
from wappalyzerjs import get_detection_script

script = get_detection_script()  # 'full' or 'curated'
results = await page.evaluate(script + "; wappalyzerjs.detect()")
```

### CLI

```bash
npm run scan -- https://example.com
npm run scan -- https://example.com --json
```

## Detection output

```json
{
  "name": "Next.js",
  "version": "14.2.30",
  "confidence": 100,
  "categories": [12, 18],
  "categoryNames": ["JavaScript frameworks", "Web frameworks"],
  "cpe": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
  "evidence": [
    { "type": "js", "key": "window.__NEXT_DATA__" },
    { "type": "js", "key": "window.next.version", "matched": "14.2.30" },
    { "type": "dom", "key": "#__next" }
  ]
}
```

## Update rules

Fetch the latest rules from the Wappalyzer database and rebuild the Python bundle:

```bash
npm run fetch-rules
npm run build:python
```

## License

MIT
