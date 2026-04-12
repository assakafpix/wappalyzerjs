import { describe, it, expect, beforeEach, vi } from 'vitest';

// We test the pure logic functions by mocking the browser globals

// Mock window and document for Node environment
const mockWindow: Record<string, unknown> = {};
const mockElements: Map<string, Element[]> = new Map();
const mockScripts: Array<{ src: string }> = [];

vi.stubGlobal('window', mockWindow);
vi.stubGlobal('document', {
  querySelectorAll: (selector: string) => {
    if (selector === 'script[src]') {
      return mockScripts.map((s) => ({
        getAttribute: (name: string) => (name === 'src' ? s.src : null),
      }));
    }
    return mockElements.get(selector) ?? [];
  },
});

// Import after mocking
const { detect } = await import('../src/detect.js');
import type { TechnologyDefinition } from '../src/types.js';

const resetMocks = () => {
  for (const key of Object.keys(mockWindow)) {
    delete mockWindow[key];
  }
  mockElements.clear();
  mockScripts.length = 0;
};

describe('detect', () => {
  beforeEach(resetMocks);

  it('detects technology via JS global existence', () => {
    mockWindow['jQuery'] = () => {};
    const techs: TechnologyDefinition[] = [
      { name: 'jQuery', categories: [59], js: [{ property: 'jQuery', pattern: '' }] },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
    expect(results[0].name).toBe('jQuery');
    expect(results[0].evidence[0].type).toBe('js');
    expect(results[0].evidence[0].key).toBe('window.jQuery');
  });

  it('extracts version from JS global', () => {
    mockWindow['jQuery'] = { fn: { jquery: '3.7.1' } };
    const techs: TechnologyDefinition[] = [
      {
        name: 'jQuery',
        categories: [59],
        js: [{ property: 'jQuery.fn.jquery', pattern: '([\\d.]+)\\;version:\\1' }],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
    expect(results[0].version).toBe('3.7.1');
  });

  it('detects technology via DOM selector', () => {
    mockElements.set('[data-reactroot]', [{ textContent: '' } as unknown as Element]);
    const techs: TechnologyDefinition[] = [
      {
        name: 'React',
        categories: [12],
        dom: [{ selector: '[data-reactroot]', check: { type: 'exists' } }],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
    expect(results[0].name).toBe('React');
    expect(results[0].evidence[0].type).toBe('dom');
  });

  it('extracts version from DOM attribute', () => {
    mockElements.set('[ng-version]', [
      {
        getAttribute: (name: string) => (name === 'ng-version' ? '17.3.0' : null),
        textContent: '',
      } as unknown as Element,
    ]);
    const techs: TechnologyDefinition[] = [
      {
        name: 'Angular',
        categories: [12],
        dom: [
          {
            selector: '[ng-version]',
            check: {
              type: 'attribute',
              name: 'ng-version',
              pattern: '([\\d.]+)\\;version:\\1',
            },
          },
        ],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
    expect(results[0].version).toBe('17.3.0');
  });

  it('detects technology via script src', () => {
    mockScripts.push({ src: 'https://cdn.example.com/jquery-3.7.1.min.js' });
    const techs: TechnologyDefinition[] = [
      {
        name: 'jQuery',
        categories: [59],
        scripts: [{ pattern: 'jquery[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1' }],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
    expect(results[0].name).toBe('jQuery');
    expect(results[0].version).toBe('3.7.1');
    expect(results[0].evidence[0].type).toBe('script');
  });

  it('resolves implied technologies', () => {
    mockWindow['__NEXT_DATA__'] = {};
    const techs: TechnologyDefinition[] = [
      {
        name: 'Next.js',
        categories: [12],
        js: [{ property: '__NEXT_DATA__', pattern: '' }],
        implies: ['React', 'Node.js'],
      },
      { name: 'React', categories: [12] },
      { name: 'Node.js', categories: [27] },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(3);
    const names = results.map((r) => r.name).sort();
    expect(names).toEqual(['Next.js', 'Node.js', 'React']);
  });

  it('returns empty array when nothing matches', () => {
    const techs: TechnologyDefinition[] = [
      { name: 'jQuery', categories: [59], js: [{ property: 'jQuery', pattern: '' }] },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(0);
  });

  it('deduplicates implied technologies', () => {
    mockWindow['Shopify'] = {};
    mockWindow['ShopifyAnalytics'] = {};
    const techs: TechnologyDefinition[] = [
      {
        name: 'Shopify',
        categories: [6],
        js: [{ property: 'Shopify', pattern: '' }],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
  });

  it('combines evidence from multiple checks', () => {
    mockWindow['jQuery'] = { fn: { jquery: '3.7.1' } };
    mockScripts.push({ src: 'https://cdn.example.com/jquery-3.7.1.min.js' });
    const techs: TechnologyDefinition[] = [
      {
        name: 'jQuery',
        categories: [59],
        js: [
          { property: 'jQuery', pattern: '' },
          { property: 'jQuery.fn.jquery', pattern: '([\\d.]+)\\;version:\\1' },
        ],
        scripts: [{ pattern: 'jquery[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1' }],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
    expect(results[0].evidence.length).toBeGreaterThanOrEqual(2);
    expect(results[0].version).toBe('3.7.1');
  });

  it('handles nested window properties', () => {
    mockWindow['__REACT_DEVTOOLS_GLOBAL_HOOK__'] = { renderers: new Map() };
    const techs: TechnologyDefinition[] = [
      {
        name: 'React',
        categories: [12],
        js: [{ property: '__REACT_DEVTOOLS_GLOBAL_HOOK__', pattern: '' }],
      },
    ];
    const results = detect(techs);
    expect(results).toHaveLength(1);
  });
});
