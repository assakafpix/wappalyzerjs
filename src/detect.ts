import type {
  TechnologyDefinition,
  DetectedTechnology,
  DetectionEvidence,
  JsRule,
  DomRule,
  ScriptRule,
} from './types.js';
import { technologies } from './technologies.js';

// ---- Pattern parsing ----

interface ParsedPattern {
  regex: RegExp | null;
  /** Extract version from capture group \1 */
  versionGroup: number | null;
  /** Confidence modifier (0-100), default 100 */
  confidence: number;
}

const parsePattern = (raw: string): ParsedPattern => {
  if (!raw) return { regex: null, versionGroup: null, confidence: 100 };

  let pattern = raw;
  let versionGroup: number | null = null;
  let confidence = 100;

  // Extract ";version:\1" suffix
  const versionMatch = pattern.match(/\\;version:\\(\d+)/);
  if (versionMatch) {
    versionGroup = parseInt(versionMatch[1], 10);
    pattern = pattern.replace(/\\;version:\\(\d+)/, '');
  }

  // Extract ";confidence:N" suffix
  const confMatch = pattern.match(/\\;confidence:(\d+)/);
  if (confMatch) {
    confidence = parseInt(confMatch[1], 10);
    pattern = pattern.replace(/\\;confidence:(\d+)/, '');
  }

  try {
    return { regex: new RegExp(pattern, 'i'), versionGroup, confidence };
  } catch {
    return { regex: null, versionGroup: null, confidence };
  }
};

const extractVersion = (match: RegExpMatchArray, versionGroup: number | null): string => {
  if (versionGroup === null) return '';
  return match[versionGroup] ?? '';
};

// ---- JS global detection ----

const resolveProperty = (obj: unknown, path: string): unknown => {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
};

const safeString = (value: unknown): string => {
  try {
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (typeof value === 'function') return '[function]';
    return typeof value;
  } catch {
    return '[object]';
  }
};

const checkJsRule = (rule: JsRule): { matched: boolean; version: string; confidence: number; value?: string } => {
  const value = resolveProperty(window, rule.property);
  if (value === undefined) return { matched: false, version: '', confidence: 0 };

  if (!rule.pattern) {
    return { matched: true, version: '', confidence: 100, value: safeString(value) };
  }

  const parsed = parsePattern(rule.pattern);
  if (!parsed.regex) {
    return { matched: true, version: '', confidence: parsed.confidence, value: safeString(value) };
  }

  const strValue = safeString(value);
  const match = strValue.match(parsed.regex);
  if (!match) {
    // Property exists but doesn't match pattern — still counts as existence
    return { matched: true, version: '', confidence: Math.min(parsed.confidence, 50), value: strValue };
  }

  return {
    matched: true,
    version: extractVersion(match, parsed.versionGroup),
    confidence: parsed.confidence,
    value: strValue,
  };
};

// ---- DOM detection ----

const checkDomRule = (rule: DomRule): { matched: boolean; version: string; confidence: number; value?: string } => {
  let elements: NodeListOf<Element>;
  try {
    elements = document.querySelectorAll(rule.selector);
  } catch {
    return { matched: false, version: '', confidence: 0 };
  }

  if (elements.length === 0) return { matched: false, version: '', confidence: 0 };

  if (rule.check.type === 'exists') {
    return { matched: true, version: '', confidence: 100 };
  }

  for (const el of elements) {
    if (rule.check.type === 'attribute') {
      const attrValue = el.getAttribute(rule.check.name);
      if (attrValue === null) continue;
      const parsed = parsePattern(rule.check.pattern);
      if (!parsed.regex) {
        return { matched: true, version: '', confidence: parsed.confidence, value: attrValue };
      }
      const match = attrValue.match(parsed.regex);
      if (match) {
        return {
          matched: true,
          version: extractVersion(match, parsed.versionGroup),
          confidence: parsed.confidence,
          value: attrValue,
        };
      }
    }

    if (rule.check.type === 'property') {
      const propValue = (el as unknown as Record<string, unknown>)[rule.check.name];
      if (propValue === undefined) continue;
      const strValue = String(propValue);
      const parsed = parsePattern(rule.check.pattern);
      if (!parsed.regex) {
        return { matched: true, version: '', confidence: parsed.confidence, value: strValue };
      }
      const match = strValue.match(parsed.regex);
      if (match) {
        return {
          matched: true,
          version: extractVersion(match, parsed.versionGroup),
          confidence: parsed.confidence,
          value: strValue,
        };
      }
    }

    if (rule.check.type === 'text') {
      const textContent = el.textContent ?? '';
      const parsed = parsePattern(rule.check.pattern);
      if (!parsed.regex) {
        return { matched: true, version: '', confidence: parsed.confidence, value: textContent.slice(0, 200) };
      }
      const match = textContent.match(parsed.regex);
      if (match) {
        return {
          matched: true,
          version: extractVersion(match, parsed.versionGroup),
          confidence: parsed.confidence,
          value: textContent.slice(0, 200),
        };
      }
    }
  }

  return { matched: false, version: '', confidence: 0 };
};

// ---- Script src detection ----

const checkScriptRule = (rule: ScriptRule): { matched: boolean; version: string; confidence: number; value?: string } => {
  const scripts = document.querySelectorAll('script[src]');
  const parsed = parsePattern(rule.pattern);

  for (const script of scripts) {
    const src = script.getAttribute('src') ?? '';
    if (!parsed.regex) {
      if (src.includes(rule.pattern)) {
        return { matched: true, version: '', confidence: parsed.confidence, value: src };
      }
      continue;
    }
    const match = src.match(parsed.regex);
    if (match) {
      return {
        matched: true,
        version: extractVersion(match, parsed.versionGroup),
        confidence: parsed.confidence,
        value: src,
      };
    }
  }

  return { matched: false, version: '', confidence: 0 };
};

// ---- PURL generation (mirrors nohehf/wappalyzergo) ----

/** Wappalyzer category IDs that correspond to package-type technologies */
const packageCategoryIds = new Set([
  12, // JavaScript frameworks
  59, // JavaScript libraries
  25, // JavaScript graphics
  18, // Web frameworks
  66, // UI frameworks
  26, // Mobile frameworks
  24, // Rich text editors
  37, // Editors
  54, // WordPress plugins
  100, // Shopify apps
  103, // Drupal themes
  97, // WordPress themes
]);

/** Category ID → package registry type */
const categoryPackageType: Record<number, string> = {
  12: 'npm', 59: 'npm', 25: 'npm', 26: 'npm', 66: 'npm', 24: 'npm', 37: 'npm',
  54: 'generic', 97: 'generic', 103: 'generic',
};

/** CPE vendor → package registry type */
const cpeVendorPackageType: Record<string, string> = {
  expressjs: 'npm', jquery: 'npm', angularjs: 'npm', vuejs: 'npm',
  nodejs: 'npm', zeit: 'npm', vercel: 'npm', facebook: 'npm',
  getbootstrap: 'npm', nuxtjs: 'npm', gatsbyjs: 'npm',
  datatables: 'npm', sencha: 'npm', formstone: 'npm',
  ckeditor: 'npm', tiny: 'npm',
  djangoproject: 'pypi', palletsprojects: 'pypi', encode: 'pypi', tiangolo: 'pypi',
  laravel: 'composer', symfony: 'composer', cakephp: 'composer',
  rubyonrails: 'gem',
  vmware: 'maven', pivotal_software: 'maven', lightbend: 'maven', playframework: 'maven',
  microsoft: 'nuget',
};

const inferPurl = (name: string, version: string, categories: number[], cpe?: string): string | undefined => {
  // Only package-type technologies get PURLs (software is identified by CPE or normalized name)
  if (!categories.some((c) => packageCategoryIds.has(c))) return undefined;

  // Determine package type: CPE vendor → category → generic
  let pkgType = 'generic';

  if (cpe) {
    const vendor = cpe.split(':')[3] ?? '';
    if (vendor && cpeVendorPackageType[vendor]) {
      pkgType = cpeVendorPackageType[vendor];
    }
  }

  if (pkgType === 'generic') {
    for (const cat of categories) {
      if (categoryPackageType[cat]) {
        pkgType = categoryPackageType[cat];
        break;
      }
    }
  }

  const pkgName = name.toLowerCase().replace(/ /g, '-');
  const versionSuffix = version ? `@${version}` : '';
  return `pkg:${pkgType}/${pkgName}${versionSuffix}`;
};

// ---- Main detection ----

const detectTechnology = (tech: TechnologyDefinition): DetectedTechnology | null => {
  const evidence: DetectionEvidence[] = [];
  let bestVersion = '';
  let totalConfidence = 0;
  let checksRun = 0;

  // Check JS globals
  if (tech.js) {
    for (const rule of tech.js) {
      const result = checkJsRule(rule);
      if (result.matched) {
        evidence.push({ type: 'js', key: `window.${rule.property}`, matched: result.value });
        if (result.version) bestVersion = result.version;
        totalConfidence = Math.max(totalConfidence, result.confidence);
      }
      checksRun++;
    }
  }

  // Check DOM
  if (tech.dom) {
    for (const rule of tech.dom) {
      const result = checkDomRule(rule);
      if (result.matched) {
        evidence.push({ type: 'dom', key: rule.selector, matched: result.value });
        if (result.version) bestVersion = result.version;
        totalConfidence = Math.max(totalConfidence, result.confidence);
      }
      checksRun++;
    }
  }

  // Check script src
  if (tech.scripts) {
    for (const rule of tech.scripts) {
      const result = checkScriptRule(rule);
      if (result.matched) {
        evidence.push({ type: 'script', key: rule.pattern, matched: result.value });
        if (result.version) bestVersion = result.version;
        totalConfidence = Math.max(totalConfidence, result.confidence);
      }
      checksRun++;
    }
  }

  if (evidence.length === 0) return null;

  // Inject detected version into CPE wildcard
  let cpe = tech.cpe;
  if (cpe && bestVersion) {
    cpe = cpe.replace(':*:', `:${bestVersion}:`).replace(':-:', `:${bestVersion}:`);
  }

  // Generate PURL for package-type technologies
  const purl = inferPurl(tech.name, bestVersion, tech.categories, cpe);

  return {
    name: tech.name,
    version: bestVersion,
    confidence: totalConfidence,
    categories: tech.categories,
    categoryNames: tech.categoryNames,
    website: tech.website,
    description: tech.description,
    cpe,
    purl,
    evidence,
  };
};

/** Run all technology detections against the current page. Call via page.evaluate(). */
export const detect = (customTechnologies?: TechnologyDefinition[]): DetectedTechnology[] => {
  const techs = customTechnologies ?? technologies;
  const results: DetectedTechnology[] = [];

  for (const tech of techs) {
    const result = detectTechnology(tech);
    if (result) results.push(result);
  }

  // Resolve implies
  const detectedNames = new Set(results.map((r) => r.name));
  for (const result of results) {
    const tech = techs.find((t) => t.name === result.name);
    if (tech?.implies) {
      for (const implied of tech.implies) {
        // Strip confidence modifier from implies (e.g. "PHP\\;confidence:50")
        const impliedName = implied.replace(/\\;confidence:\d+/, '').trim();
        if (!detectedNames.has(impliedName)) {
          const impliedTech = techs.find((t) => t.name === impliedName);
          if (impliedTech) {
            detectedNames.add(impliedName);
            results.push({
              name: impliedName,
              version: '',
              confidence: 50,
              categories: impliedTech.categories,
              categoryNames: impliedTech.categoryNames,
              website: impliedTech.website,
              description: impliedTech.description,
              cpe: impliedTech.cpe,
              purl: inferPurl(impliedName, '', impliedTech.categories, impliedTech.cpe),
              evidence: [{ type: 'js', key: `implied by ${result.name}` }],
            });
          }
        }
      }
    }
  }

  return results;
};
