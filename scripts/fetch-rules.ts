/**
 * Fetches the full Wappalyzer/webappanalyzer technologies database
 * and extracts JS + DOM detection rules into our format.
 *
 * Usage: npx tsx scripts/fetch-rules.ts
 *
 * Sources:
 * - https://github.com/AliasIO/wappalyzer (original, archived)
 * - https://github.com/AliasIO/wappalyzer (categories)
 * - https://github.com/AliasIO/wappalyzer (technologies JSONs)
 */

import { writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { TechnologyDefinition, JsRule, DomRule, ScriptRule } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const WAPPALYZER_BASE =
  'https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies';

const CATEGORIES_URL =
  'https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/categories.json';

// Wappalyzer splits technologies into a-z JSON files
const TECH_FILES = 'abcdefghijklmnopqrstuvwxyz_'.split('').map(
  (c) => `${WAPPALYZER_BASE}/${c}.json`
);

interface WappalyzerTech {
  cats?: number[];
  website?: string;
  description?: string;
  cpe?: string;
  js?: Record<string, string>;
  dom?: string | string[] | Record<string, Record<string, string>>;
  scripts?: string | string[];
  implies?: string | string[];
  [key: string]: unknown;
}

const toArray = (v: string | string[] | undefined): string[] => {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
};

const convertJsRules = (js: Record<string, string>): JsRule[] =>
  Object.entries(js).map(([property, pattern]) => ({ property, pattern }));

const convertDomRules = (
  dom: string | string[] | Record<string, Record<string, string>>
): DomRule[] => {
  if (typeof dom === 'string') {
    return [{ selector: dom, check: { type: 'exists' } }];
  }

  if (Array.isArray(dom)) {
    return dom.map((selector) => ({ selector, check: { type: 'exists' as const } }));
  }

  // Object form: { "selector": { "attribute": "pattern", "text": "pattern", ... } }
  const rules: DomRule[] = [];
  for (const [selector, checks] of Object.entries(dom)) {
    if (!checks || Object.keys(checks).length === 0) {
      rules.push({ selector, check: { type: 'exists' } });
      continue;
    }

    for (const [checkType, pattern] of Object.entries(checks)) {
      if (checkType === 'exists') {
        rules.push({ selector, check: { type: 'exists' } });
      } else if (checkType === 'text') {
        rules.push({
          selector,
          check: { type: 'text', pattern: typeof pattern === 'string' ? pattern : '' },
        });
      } else if (checkType === 'properties') {
        // properties is a nested object { propName: pattern }
        if (typeof pattern === 'object' && pattern !== null) {
          for (const [prop, propPattern] of Object.entries(
            pattern as Record<string, string>
          )) {
            rules.push({
              selector,
              check: { type: 'property', name: prop, pattern: typeof propPattern === 'string' ? propPattern : '' },
            });
          }
        }
      } else if (checkType === 'attributes') {
        // attributes is a nested object { attrName: pattern }
        if (typeof pattern === 'object' && pattern !== null) {
          for (const [attr, attrPattern] of Object.entries(
            pattern as Record<string, string>
          )) {
            rules.push({
              selector,
              check: { type: 'attribute', name: attr, pattern: typeof attrPattern === 'string' ? attrPattern : '' },
            });
          }
        }
      } else {
        // Treat as direct attribute check: { "href": "pattern" }
        rules.push({
          selector,
          check: { type: 'attribute', name: checkType, pattern: typeof pattern === 'string' ? pattern : '' },
        });
      }
    }
  }
  return rules;
};

const convertScriptRules = (scripts: string | string[]): ScriptRule[] =>
  toArray(scripts).map((pattern) => ({ pattern }));

const main = async () => {
  console.log('Fetching Wappalyzer technologies...');

  // Fetch categories
  let categories: Record<string, { name: string }> = {};
  try {
    const res = await fetch(CATEGORIES_URL);
    if (res.ok) {
      categories = await res.json() as Record<string, { name: string }>;
      console.log(`  Loaded ${Object.keys(categories).length} categories`);
    }
  } catch (e) {
    console.warn('  Could not fetch categories, continuing without names');
  }

  // Fetch all technology files
  const allTechs: TechnologyDefinition[] = [];
  let skipped = 0;

  for (const url of TECH_FILES) {
    const letter = url.split('/').pop()?.replace('.json', '') ?? '?';
    try {
      const res = await fetch(url);
      if (!res.ok) {
        console.warn(`  Skipping ${letter}.json (${res.status})`);
        continue;
      }
      const data = (await res.json()) as Record<string, WappalyzerTech>;
      console.log(`  ${letter}.json: ${Object.keys(data).length} technologies`);

      for (const [name, tech] of Object.entries(data)) {
        const hasJs = tech.js && Object.keys(tech.js).length > 0;
        const hasDom = tech.dom && (typeof tech.dom === 'string' || Array.isArray(tech.dom) || Object.keys(tech.dom).length > 0);
        const hasScripts = tech.scripts && toArray(tech.scripts as string | string[]).length > 0;

        // Only include technologies with browser-detectable rules
        if (!hasJs && !hasDom && !hasScripts) {
          skipped++;
          continue;
        }

        const cats = tech.cats ?? [];
        const def: TechnologyDefinition = {
          name,
          categories: cats,
          categoryNames: cats.map((c) => categories[String(c)]?.name).filter(Boolean),
          website: tech.website,
          description: tech.description,
          cpe: tech.cpe,
        };

        if (hasJs) def.js = convertJsRules(tech.js!);
        if (hasDom) def.dom = convertDomRules(tech.dom!);
        if (hasScripts) def.scripts = convertScriptRules(tech.scripts as string | string[]);
        if (tech.implies) def.implies = toArray(tech.implies as string | string[]);

        allTechs.push(def);
      }
    } catch (e) {
      console.warn(`  Error fetching ${letter}.json: ${e}`);
    }
  }

  console.log(`\nTotal: ${allTechs.length} browser-detectable technologies (${skipped} skipped — HTTP-only)`);

  // Write output
  const outPath = resolve(__dirname, '../src/technologies.generated.ts');
  const content = `// AUTO-GENERATED by scripts/fetch-rules.ts — do not edit manually
// Source: https://github.com/enthec/webappanalyzer
// Generated: ${new Date().toISOString()}

import type { TechnologyDefinition } from './types.js';

export const generatedTechnologies: TechnologyDefinition[] = ${JSON.stringify(allTechs, null, 2)};
`;

  writeFileSync(outPath, content, 'utf-8');
  console.log(`\nWritten to ${outPath}`);
};

main().catch(console.error);
