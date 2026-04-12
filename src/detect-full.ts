/**
 * Full detection entry point — uses the complete Wappalyzer database (4900+ technologies).
 * Builds into detect-full.bundle.js for comprehensive scanning.
 *
 * Usage (via page.evaluate):
 *   const results = await page.evaluate(bundleScript + '; wappalyzerjs.detect()');
 */
import type { TechnologyDefinition, DetectedTechnology } from './types.js';
import { generatedTechnologies } from './technologies.generated.js';
import { technologies as curatedTechnologies } from './technologies.js';

// Merge: generated first, then curated rules not already in generated
const allTechnologies: TechnologyDefinition[] = [
  ...generatedTechnologies,
  ...curatedTechnologies.filter(
    (curated) => !generatedTechnologies.some((gen) => gen.name === curated.name),
  ),
];

// Re-import the detection engine but don't use its default technologies
// Instead, we inline the detect function with our full set
export { allTechnologies as technologies };

// Re-export detect, but with full technologies as default
import { detect as _detect } from './detect.js';
export const detect = (customTechnologies?: TechnologyDefinition[]): DetectedTechnology[] =>
  _detect(customTechnologies ?? allTechnologies);
