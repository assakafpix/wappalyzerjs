#!/usr/bin/env node
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { chromium } from 'playwright';
import { technologies } from './technologies.js';
import type { DetectedTechnology } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const url = process.argv[2];
if (!url) {
  console.error('Usage: wappalyzerjs <url> [--json] [--headless]');
  process.exit(1);
}

const flags = new Set(process.argv.slice(3));
const jsonOutput = flags.has('--json');
const headless = !flags.has('--headed');

const main = async () => {
  // Read the bundled detection script
  let detectScript: string;
  try {
    detectScript = readFileSync(resolve(__dirname, '../dist/detect.bundle.js'), 'utf-8');
  } catch {
    // Fallback: inline the detect function with technologies for dev mode (tsx)
    const { detect } = await import('./detect.js');
    detectScript = '';

    // We'll use page.evaluate with a function instead
    const browser = await chromium.launch({ headless });
    const page = await browser.newPage();

    if (!jsonOutput) console.log(`Scanning ${url}...`);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await page.waitForTimeout(3000);

    // Serialize technologies and inject detect function
    const results: DetectedTechnology[] = await page.evaluate(
      ({ techs }) => {
        // -- everything below runs in browser context --

        const parsePattern = (raw: string) => {
          if (!raw) return { regex: null, versionGroup: null, confidence: 100 };
          let pattern = raw;
          let versionGroup: number | null = null;
          let confidence = 100;
          const vm = pattern.match(/\\;version:\\(\d+)/);
          if (vm) { versionGroup = parseInt(vm[1], 10); pattern = pattern.replace(/\\;version:\\(\d+)/, ''); }
          const cm = pattern.match(/\\;confidence:(\d+)/);
          if (cm) { confidence = parseInt(cm[1], 10); pattern = pattern.replace(/\\;confidence:(\d+)/, ''); }
          try { return { regex: new RegExp(pattern, 'i'), versionGroup, confidence }; }
          catch { return { regex: null, versionGroup: null, confidence }; }
        };

        const extractVersion = (match: RegExpMatchArray, vg: number | null) =>
          vg === null ? '' : (match[vg] ?? '');

        const resolveProperty = (obj: any, path: string): any => {
          const parts = path.split('.');
          let cur = obj;
          for (const p of parts) { if (cur == null || typeof cur !== 'object') return undefined; cur = cur[p]; }
          return cur;
        };

        const results: any[] = [];
        const detectedNames = new Set<string>();

        for (const tech of techs) {
          const evidence: any[] = [];
          let bestVersion = '';
          let totalConfidence = 0;

          if (tech.js) {
            for (const rule of tech.js) {
              const value = resolveProperty(window, rule.property);
              if (value === undefined) continue;
              if (!rule.pattern) {
                evidence.push({ type: 'js', key: `window.${rule.property}`, matched: String(value).slice(0, 100) });
                totalConfidence = Math.max(totalConfidence, 100);
                continue;
              }
              const p = parsePattern(rule.pattern);
              const strVal = String(value);
              if (!p.regex) { evidence.push({ type: 'js', key: `window.${rule.property}` }); totalConfidence = Math.max(totalConfidence, p.confidence); continue; }
              const m = strVal.match(p.regex);
              if (m) {
                const v = extractVersion(m, p.versionGroup);
                if (v) bestVersion = v;
                evidence.push({ type: 'js', key: `window.${rule.property}`, matched: strVal.slice(0, 100) });
                totalConfidence = Math.max(totalConfidence, p.confidence);
              } else {
                evidence.push({ type: 'js', key: `window.${rule.property}`, matched: strVal.slice(0, 100) });
                totalConfidence = Math.max(totalConfidence, Math.min(p.confidence, 50));
              }
            }
          }

          if (tech.dom) {
            for (const rule of tech.dom) {
              let els: NodeListOf<Element>;
              try { els = document.querySelectorAll(rule.selector); } catch { continue; }
              if (els.length === 0) continue;
              if (rule.check.type === 'exists') {
                evidence.push({ type: 'dom', key: rule.selector });
                totalConfidence = Math.max(totalConfidence, 100);
                continue;
              }
              for (const el of els) {
                if (rule.check.type === 'attribute') {
                  const av = el.getAttribute(rule.check.name);
                  if (av === null) continue;
                  const p = parsePattern(rule.check.pattern);
                  if (!p.regex) { evidence.push({ type: 'dom', key: rule.selector, matched: av }); totalConfidence = Math.max(totalConfidence, p.confidence); break; }
                  const m = av.match(p.regex);
                  if (m) { const v = extractVersion(m, p.versionGroup); if (v) bestVersion = v; evidence.push({ type: 'dom', key: rule.selector, matched: av }); totalConfidence = Math.max(totalConfidence, p.confidence); break; }
                }
                if (rule.check.type === 'text') {
                  const txt = el.textContent ?? '';
                  const p = parsePattern(rule.check.pattern);
                  if (!p.regex) { evidence.push({ type: 'dom', key: rule.selector, matched: txt.slice(0, 100) }); totalConfidence = Math.max(totalConfidence, p.confidence); break; }
                  const m = txt.match(p.regex);
                  if (m) { const v = extractVersion(m, p.versionGroup); if (v) bestVersion = v; evidence.push({ type: 'dom', key: rule.selector, matched: txt.slice(0, 100) }); totalConfidence = Math.max(totalConfidence, p.confidence); break; }
                }
              }
            }
          }

          if (tech.scripts) {
            const scriptEls = document.querySelectorAll('script[src]');
            for (const rule of tech.scripts) {
              const p = parsePattern(rule.pattern);
              for (const s of scriptEls) {
                const src = s.getAttribute('src') ?? '';
                if (!p.regex) { if (src.includes(rule.pattern)) { evidence.push({ type: 'script', key: rule.pattern, matched: src }); totalConfidence = Math.max(totalConfidence, p.confidence); break; } continue; }
                const m = src.match(p.regex);
                if (m) { const v = extractVersion(m, p.versionGroup); if (v) bestVersion = v; evidence.push({ type: 'script', key: rule.pattern, matched: src }); totalConfidence = Math.max(totalConfidence, p.confidence); break; }
              }
            }
          }

          if (evidence.length === 0) continue;
          detectedNames.add(tech.name);
          results.push({
            name: tech.name, version: bestVersion, confidence: totalConfidence,
            categories: tech.categories, categoryNames: tech.categoryNames,
            website: tech.website, cpe: tech.cpe, evidence,
          });
        }

        // Resolve implies
        for (const r of [...results]) {
          const tech = techs.find((t: any) => t.name === r.name);
          if (!tech?.implies) continue;
          for (const imp of tech.implies) {
            const impliedName = imp.replace(/\\;confidence:\d+/, '').trim();
            if (detectedNames.has(impliedName)) continue;
            const impliedTech = techs.find((t: any) => t.name === impliedName);
            if (!impliedTech) continue;
            detectedNames.add(impliedName);
            results.push({
              name: impliedName, version: '', confidence: 50,
              categories: impliedTech.categories, categoryNames: impliedTech.categoryNames,
              website: impliedTech.website, cpe: impliedTech.cpe,
              evidence: [{ type: 'js', key: `implied by ${r.name}` }],
            });
          }
        }

        return results;
      },
      { techs: technologies },
    );

    await browser.close();
    printResults(results);
    return;
  }

  // Production path: use the pre-built bundle
  const browser = await chromium.launch({ headless });
  const page = await browser.newPage();

  if (!jsonOutput) console.log(`Scanning ${url}...`);

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.waitForTimeout(3000);

  const results: DetectedTechnology[] = await page.evaluate(
    detectScript + '; wappalyzerjs.detect();',
  );

  await browser.close();
  printResults(results);
};

const printResults = (results: DetectedTechnology[]) => {
  if (jsonOutput) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  if (results.length === 0) {
    console.log('No technologies detected.');
    return;
  }

  console.log(`\nDetected ${results.length} technologies:\n`);

  // Sort by confidence desc, then name
  results.sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));

  for (const tech of results) {
    const version = tech.version ? ` v${tech.version}` : '';
    const cats = tech.categoryNames?.length ? ` (${tech.categoryNames.join(', ')})` : '';
    const conf = tech.confidence < 100 ? ` [${tech.confidence}%]` : '';

    console.log(`  ${tech.name}${version}${cats}${conf}`);

    for (const ev of tech.evidence) {
      const matched = ev.matched ? ` → ${ev.matched.slice(0, 80)}` : '';
      console.log(`    ${ev.type}: ${ev.key}${matched}`);
    }
    console.log();
  }
};

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
