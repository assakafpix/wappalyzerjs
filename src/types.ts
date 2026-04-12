// ---- Detection rule definitions ----

/** A JS global check: property path on window → pattern with optional version extraction */
export interface JsRule {
  /** Dot-separated path on window, e.g. "jQuery.fn.jquery" */
  property: string;
  /**
   * Regex pattern to match against the resolved value (stringified).
   * Empty string = existence check only.
   * Can include ";version:\1" suffix for version extraction.
   */
  pattern: string;
}

/** A DOM-based check: CSS selector → what to inspect on matched elements */
export interface DomRule {
  /** CSS selector, e.g. "[data-reactroot]", "script[src*='jquery']" */
  selector: string;
  /** What to check on matched elements */
  check:
    | { type: 'exists' }
    | { type: 'attribute'; name: string; pattern: string }
    | { type: 'property'; name: string; pattern: string }
    | { type: 'text'; pattern: string };
}

/** A script src check: regex matched against all <script src="..."> on the page */
export interface ScriptRule {
  /** Regex pattern to match against script src URLs */
  pattern: string;
}

/** Full technology detection definition */
export interface TechnologyDefinition {
  name: string;
  categories: number[];
  categoryNames?: string[];
  website?: string;
  description?: string;
  cpe?: string;
  /** JS global variable checks (runs in browser context) */
  js?: JsRule[];
  /** DOM element checks (runs in browser context) */
  dom?: DomRule[];
  /** Script src URL pattern checks (runs in browser context) */
  scripts?: ScriptRule[];
  /** Technology implies other technologies */
  implies?: string[];
}

// ---- Detection results ----

export interface DetectionEvidence {
  type: 'js' | 'dom' | 'script';
  /** What matched — e.g. "window.jQuery", "[data-reactroot]", "script[src*='react']" */
  key: string;
  /** The matched value (if any) */
  matched?: string;
}

export interface DetectedTechnology {
  name: string;
  version: string;
  confidence: number;
  categories: number[];
  categoryNames?: string[];
  website?: string;
  description?: string;
  cpe?: string;
  purl?: string;
  evidence: DetectionEvidence[];
}

// ---- Categories ----

export interface Category {
  id: number;
  name: string;
}
