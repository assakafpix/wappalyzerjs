import type { TechnologyDefinition } from './types.js';

/**
 * Curated technology detection rules for browser-side detection.
 * These cover JS globals, DOM patterns, and script src checks
 * that HTTP-level fingerprinting (wappalyzergo) cannot detect.
 */
export const technologies: TechnologyDefinition[] = [
  // ============================================================
  // JavaScript Frameworks & Libraries
  // ============================================================
  {
    name: 'jQuery',
    categories: [59],
    categoryNames: ['JavaScript libraries'],
    website: 'https://jquery.com',
    cpe: 'cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*',
    js: [
      { property: 'jQuery', pattern: '' },
      { property: 'jQuery.fn.jquery', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    scripts: [{ pattern: 'jquery[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1' }],
  },
  {
    name: 'jQuery UI',
    categories: [59],
    categoryNames: ['JavaScript libraries'],
    website: 'https://jqueryui.com',
    cpe: 'cpe:2.3:a:jquery:jquery_ui:*:*:*:*:*:*:*:*',
    js: [{ property: 'jQuery.ui', pattern: '' }, { property: 'jQuery.ui.version', pattern: '([\\d.]+)\\;version:\\1' }],
    implies: ['jQuery'],
  },
  {
    name: 'React',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://reactjs.org',
    cpe: 'cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*',
    js: [
      { property: '__REACT_DEVTOOLS_GLOBAL_HOOK__', pattern: '' },
      { property: 'React.version', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    dom: [
      { selector: '[data-reactroot]', check: { type: 'exists' } },
      { selector: '[data-reactid]', check: { type: 'exists' } },
    ],
    scripts: [{ pattern: 'react(?:\\.production|\\.development)?(?:\\.min)?\\.js' }],
  },
  {
    name: 'Next.js',
    categories: [12, 18],
    categoryNames: ['JavaScript frameworks', 'Web frameworks'],
    website: 'https://nextjs.org',
    cpe: 'cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*',
    js: [
      { property: '__NEXT_DATA__', pattern: '' },
      { property: 'next.version', pattern: '([\\d.]+)\\;version:\\1' },
      { property: '__next', pattern: '' },
    ],
    dom: [{ selector: '#__next', check: { type: 'exists' } }],
    implies: ['React', 'Node.js'],
  },
  {
    name: 'Vue.js',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://vuejs.org',
    cpe: 'cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*',
    js: [
      { property: 'Vue', pattern: '' },
      { property: 'Vue.version', pattern: '([\\d.]+)\\;version:\\1' },
      { property: '__VUE__', pattern: '' },
    ],
    dom: [
      { selector: '[data-v-]', check: { type: 'exists' } },
      { selector: '#app[data-v-app]', check: { type: 'exists' } },
    ],
    scripts: [{ pattern: 'vue(?:\\.runtime)?(?:\\.global)?(?:\\.min)?\\.js' }],
  },
  {
    name: 'Nuxt.js',
    categories: [12, 18],
    categoryNames: ['JavaScript frameworks', 'Web frameworks'],
    website: 'https://nuxtjs.org',
    js: [
      { property: '__NUXT__', pattern: '' },
      { property: '$nuxt', pattern: '' },
      { property: '__nuxt', pattern: '' },
    ],
    dom: [{ selector: '#__nuxt', check: { type: 'exists' } }],
    implies: ['Vue.js', 'Node.js'],
  },
  {
    name: 'Angular',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://angular.io',
    cpe: 'cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*',
    js: [{ property: 'ng', pattern: '' }],
    dom: [
      { selector: '[ng-version]', check: { type: 'attribute', name: 'ng-version', pattern: '([\\d.]+)\\;version:\\1' } },
      { selector: '[ng-app]', check: { type: 'exists' } },
      { selector: 'app-root', check: { type: 'exists' } },
    ],
  },
  {
    name: 'AngularJS',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://angularjs.org',
    cpe: 'cpe:2.3:a:google:angularjs:*:*:*:*:*:*:*:*',
    js: [
      { property: 'angular', pattern: '' },
      { property: 'angular.version.full', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    dom: [
      { selector: '[ng-model]', check: { type: 'exists' } },
      { selector: '[ng-controller]', check: { type: 'exists' } },
      { selector: '[data-ng-app]', check: { type: 'exists' } },
    ],
  },
  {
    name: 'Svelte',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://svelte.dev',
    dom: [{ selector: '[class*="svelte-"]', check: { type: 'exists' } }],
  },
  {
    name: 'Ember.js',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://emberjs.com',
    js: [
      { property: 'Ember', pattern: '' },
      { property: 'Ember.VERSION', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    dom: [{ selector: '#ember-testing', check: { type: 'exists' } }],
  },
  {
    name: 'Backbone.js',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://backbonejs.org',
    js: [
      { property: 'Backbone', pattern: '' },
      { property: 'Backbone.VERSION', pattern: '([\\d.]+)\\;version:\\1' },
    ],
  },
  {
    name: 'Lodash',
    categories: [59],
    categoryNames: ['JavaScript libraries'],
    website: 'https://lodash.com',
    js: [
      { property: '_', pattern: '' },
      { property: '_.VERSION', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    scripts: [{ pattern: 'lodash(?:\\.min)?\\.js' }],
  },
  {
    name: 'Underscore.js',
    categories: [59],
    categoryNames: ['JavaScript libraries'],
    website: 'https://underscorejs.org',
    js: [{ property: '_.VERSION', pattern: '([\\d.]+)\\;version:\\1' }],
    scripts: [{ pattern: 'underscore(?:\\.min)?\\.js' }],
  },
  {
    name: 'Moment.js',
    categories: [59],
    categoryNames: ['JavaScript libraries'],
    website: 'https://momentjs.com',
    js: [
      { property: 'moment', pattern: '' },
      { property: 'moment.version', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    scripts: [{ pattern: 'moment(?:\\.min)?\\.js' }],
  },
  {
    name: 'D3',
    categories: [25],
    categoryNames: ['JavaScript graphics'],
    website: 'https://d3js.org',
    js: [
      { property: 'd3', pattern: '' },
      { property: 'd3.version', pattern: '([\\d.]+)\\;version:\\1' },
    ],
    scripts: [{ pattern: 'd3(?:\\.min)?\\.js' }],
  },
  {
    name: 'Three.js',
    categories: [25],
    categoryNames: ['JavaScript graphics'],
    website: 'https://threejs.org',
    js: [
      { property: 'THREE', pattern: '' },
      { property: 'THREE.REVISION', pattern: '(\\d+)\\;version:\\1' },
    ],
  },
  {
    name: 'Chart.js',
    categories: [25],
    categoryNames: ['JavaScript graphics'],
    website: 'https://www.chartjs.org',
    js: [{ property: 'Chart', pattern: '' }, { property: 'Chart.version', pattern: '([\\d.]+)\\;version:\\1' }],
    scripts: [{ pattern: 'chart(?:\\.min)?\\.js' }],
  },
  {
    name: 'Alpine.js',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://alpinejs.dev',
    js: [{ property: 'Alpine', pattern: '' }, { property: 'Alpine.version', pattern: '([\\d.]+)\\;version:\\1' }],
    dom: [
      { selector: '[x-data]', check: { type: 'exists' } },
      { selector: '[x-init]', check: { type: 'exists' } },
    ],
  },
  {
    name: 'HTMX',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://htmx.org',
    js: [{ property: 'htmx', pattern: '' }, { property: 'htmx.version', pattern: '([\\d.]+)\\;version:\\1' }],
    dom: [
      { selector: '[hx-get]', check: { type: 'exists' } },
      { selector: '[hx-post]', check: { type: 'exists' } },
      { selector: '[data-hx-get]', check: { type: 'exists' } },
    ],
  },
  {
    name: 'Stimulus',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://stimulus.hotwired.dev',
    dom: [
      { selector: '[data-controller]', check: { type: 'exists' } },
      { selector: '[data-action]', check: { type: 'exists' } },
    ],
  },
  {
    name: 'Turbo',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://turbo.hotwired.dev',
    js: [{ property: 'Turbo', pattern: '' }],
    dom: [
      { selector: 'turbo-frame', check: { type: 'exists' } },
      { selector: '[data-turbo]', check: { type: 'exists' } },
    ],
  },
  {
    name: 'Remix',
    categories: [12, 18],
    categoryNames: ['JavaScript frameworks', 'Web frameworks'],
    website: 'https://remix.run',
    js: [{ property: '__remixContext', pattern: '' }],
    implies: ['React'],
  },
  {
    name: 'Gatsby',
    categories: [57],
    categoryNames: ['Static site generator'],
    website: 'https://www.gatsbyjs.com',
    js: [{ property: '___gatsby', pattern: '' }],
    dom: [{ selector: '#___gatsby', check: { type: 'exists' } }],
    implies: ['React'],
  },
  {
    name: 'Astro',
    categories: [57],
    categoryNames: ['Static site generator'],
    website: 'https://astro.build',
    dom: [{ selector: 'astro-island', check: { type: 'exists' } }],
  },
  {
    name: 'SolidJS',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://www.solidjs.com',
    js: [{ property: '_$HY', pattern: '' }],
  },
  {
    name: 'Preact',
    categories: [12],
    categoryNames: ['JavaScript frameworks'],
    website: 'https://preactjs.com',
    js: [{ property: 'preact', pattern: '' }],
    dom: [{ selector: '[data-preact]', check: { type: 'exists' } }],
  },

  // ============================================================
  // Analytics & Tag Managers
  // ============================================================
  {
    name: 'Google Analytics',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://google.com/analytics',
    js: [
      { property: 'ga', pattern: '' },
      { property: 'gaGlobal', pattern: '' },
      { property: 'google_tag_data', pattern: '' },
    ],
    scripts: [
      { pattern: 'google-analytics\\.com/(?:ga|analytics)\\.js' },
      { pattern: 'googletagmanager\\.com/gtag/js' },
    ],
  },
  {
    name: 'Google Tag Manager',
    categories: [42],
    categoryNames: ['Tag managers'],
    website: 'https://tagmanager.google.com',
    js: [
      { property: 'dataLayer', pattern: '' },
      { property: 'google_tag_manager', pattern: '' },
    ],
    scripts: [{ pattern: 'googletagmanager\\.com/gtm\\.js' }],
  },
  {
    name: 'Segment',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://segment.com',
    js: [
      { property: 'analytics', pattern: '' },
      { property: 'analytics._writeKey', pattern: '' },
    ],
    scripts: [{ pattern: 'cdn\\.segment\\.com/analytics\\.js' }],
  },
  {
    name: 'Hotjar',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://www.hotjar.com',
    js: [{ property: 'hj', pattern: '' }, { property: 'hjSiteSettings', pattern: '' }],
    scripts: [{ pattern: 'static\\.hotjar\\.com' }],
  },
  {
    name: 'Mixpanel',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://mixpanel.com',
    js: [{ property: 'mixpanel', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.mxpnl\\.com' }],
  },
  {
    name: 'Amplitude',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://amplitude.com',
    js: [{ property: 'amplitude', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.amplitude\\.com' }],
  },
  {
    name: 'Heap',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://heap.io',
    js: [{ property: 'heap', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.heapanalytics\\.com' }],
  },
  {
    name: 'Plausible',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://plausible.io',
    scripts: [{ pattern: 'plausible\\.io/js/(?:plausible|script)' }],
  },
  {
    name: 'PostHog',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://posthog.com',
    js: [{ property: 'posthog', pattern: '' }],
    scripts: [{ pattern: 'us\\.i\\.posthog\\.com' }, { pattern: 'app\\.posthog\\.com' }],
  },
  {
    name: 'Facebook Pixel',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://www.facebook.com/business/tools/meta-pixel',
    js: [{ property: 'fbq', pattern: '' }],
    scripts: [{ pattern: 'connect\\.facebook\\.net/.*/fbevents\\.js' }],
  },
  {
    name: 'Microsoft Clarity',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://clarity.microsoft.com',
    js: [{ property: 'clarity', pattern: '' }],
    scripts: [{ pattern: 'clarity\\.ms/tag' }],
  },

  // ============================================================
  // Captcha Providers
  // ============================================================
  {
    name: 'reCAPTCHA',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://www.google.com/recaptcha',
    js: [{ property: 'grecaptcha', pattern: '' }],
    dom: [
      { selector: '.g-recaptcha', check: { type: 'exists' } },
      { selector: 'iframe[src*="google.com/recaptcha"]', check: { type: 'exists' } },
    ],
    scripts: [{ pattern: 'google\\.com/recaptcha' }, { pattern: 'gstatic\\.com/recaptcha' }],
  },
  {
    name: 'hCaptcha',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://www.hcaptcha.com',
    js: [{ property: 'hcaptcha', pattern: '' }],
    dom: [
      { selector: '.h-captcha', check: { type: 'exists' } },
      { selector: 'iframe[src*="hcaptcha.com"]', check: { type: 'exists' } },
    ],
    scripts: [{ pattern: 'hcaptcha\\.com/1/api\\.js' }],
  },
  {
    name: 'Cloudflare Turnstile',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://www.cloudflare.com/products/turnstile',
    js: [{ property: 'turnstile', pattern: '' }],
    dom: [{ selector: '.cf-turnstile', check: { type: 'exists' } }],
    scripts: [{ pattern: 'challenges\\.cloudflare\\.com/turnstile' }],
  },
  {
    name: 'GeeTest',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://www.geetest.com',
    js: [{ property: 'initGeetest', pattern: '' }, { property: 'initGeetest4', pattern: '' }],
    scripts: [{ pattern: 'gt\\.geetest\\.com' }],
  },
  {
    name: 'Friendly Captcha',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://friendlycaptcha.com',
    dom: [{ selector: '.frc-captcha', check: { type: 'exists' } }],
    scripts: [{ pattern: 'cdn\\.friendlycaptcha\\.com' }],
  },
  {
    name: 'AWS WAF Captcha',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://aws.amazon.com/waf',
    js: [{ property: 'AwsWafCaptcha', pattern: '' }, { property: 'AwsWafIntegration', pattern: '' }],
  },
  {
    name: 'MTCaptcha',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://www.mtcaptcha.com',
    js: [{ property: 'mtcaptcha', pattern: '' }],
    scripts: [{ pattern: 'mtcaptcha\\.com' }],
  },
  {
    name: 'Yandex SmartCaptcha',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://cloud.yandex.com/services/smartcaptcha',
    js: [{ property: 'smartCaptcha', pattern: '' }],
    scripts: [{ pattern: 'smartcaptcha\\.yandexcloud\\.net' }],
  },
  {
    name: 'FunCaptcha',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://www.arkoselabs.com',
    js: [{ property: 'ArkoseEnforcement', pattern: '' }],
    scripts: [{ pattern: 'funcaptcha\\.com' }, { pattern: 'arkoselabs\\.com' }],
  },
  {
    name: 'ALTCHA',
    categories: [16],
    categoryNames: ['Security'],
    website: 'https://altcha.org',
    dom: [{ selector: 'altcha-widget', check: { type: 'exists' } }],
    scripts: [{ pattern: 'altcha\\.org' }],
  },

  // ============================================================
  // CMS & E-commerce
  // ============================================================
  {
    name: 'WordPress',
    categories: [1],
    categoryNames: ['CMS'],
    website: 'https://wordpress.org',
    cpe: 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
    js: [{ property: 'wp', pattern: '' }, { property: 'wpApiSettings', pattern: '' }],
    dom: [
      {
        selector: 'meta[name="generator"]',
        check: { type: 'attribute', name: 'content', pattern: 'WordPress\\s?([\\d.]+)?\\;version:\\1' },
      },
      { selector: 'link[href*="wp-content"]', check: { type: 'exists' } },
      { selector: 'link[href*="wp-includes"]', check: { type: 'exists' } },
    ],
    scripts: [{ pattern: 'wp-includes/' }, { pattern: 'wp-content/' }],
    implies: ['PHP', 'MySQL'],
  },
  {
    name: 'Shopify',
    categories: [6],
    categoryNames: ['Ecommerce'],
    website: 'https://www.shopify.com',
    js: [
      { property: 'Shopify', pattern: '' },
      { property: 'ShopifyAnalytics', pattern: '' },
      { property: 'Shopify.theme', pattern: '' },
    ],
    dom: [
      { selector: 'link[href*="cdn.shopify.com"]', check: { type: 'exists' } },
      {
        selector: 'meta[name="shopify-digital-wallet"]',
        check: { type: 'exists' },
      },
    ],
    scripts: [{ pattern: 'cdn\\.shopify\\.com' }],
  },
  {
    name: 'Webflow',
    categories: [1, 51],
    categoryNames: ['CMS', 'Website builders'],
    website: 'https://webflow.com',
    js: [{ property: 'Webflow', pattern: '' }],
    dom: [
      {
        selector: 'html[data-wf-site]',
        check: { type: 'exists' },
      },
    ],
    scripts: [{ pattern: 'assets\\.website-files\\.com' }],
  },
  {
    name: 'Wix',
    categories: [1, 51],
    categoryNames: ['CMS', 'Website builders'],
    website: 'https://www.wix.com',
    js: [{ property: 'wixBiSession', pattern: '' }, { property: 'wixPerformanceMeasurements', pattern: '' }],
    dom: [
      {
        selector: 'meta[name="generator"]',
        check: { type: 'attribute', name: 'content', pattern: 'Wix\\.com' },
      },
    ],
    scripts: [{ pattern: 'static\\.parastorage\\.com' }, { pattern: 'static\\.wixstatic\\.com' }],
  },
  {
    name: 'Squarespace',
    categories: [1, 51],
    categoryNames: ['CMS', 'Website builders'],
    website: 'https://www.squarespace.com',
    js: [{ property: 'Static', pattern: '' }, { property: 'SQUARESPACE_ROLLUPS', pattern: '' }],
    dom: [
      {
        selector: 'meta[name="generator"]',
        check: { type: 'attribute', name: 'content', pattern: 'Squarespace' },
      },
    ],
    scripts: [{ pattern: 'static\\d?\\.squarespace\\.com' }],
  },
  {
    name: 'Drupal',
    categories: [1],
    categoryNames: ['CMS'],
    website: 'https://www.drupal.org',
    cpe: 'cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*',
    js: [{ property: 'Drupal', pattern: '' }],
    dom: [
      {
        selector: 'meta[name="generator"]',
        check: { type: 'attribute', name: 'content', pattern: 'Drupal\\s([\\d.]+)\\;version:\\1' },
      },
    ],
    implies: ['PHP'],
  },
  {
    name: 'Magento',
    categories: [6],
    categoryNames: ['Ecommerce'],
    website: 'https://magento.com',
    cpe: 'cpe:2.3:a:magento:magento:*:*:*:*:*:*:*:*',
    js: [{ property: 'Mage', pattern: '' }],
    scripts: [{ pattern: 'mage/cookies' }, { pattern: 'varien/js' }],
    implies: ['PHP', 'MySQL'],
  },
  {
    name: 'WooCommerce',
    categories: [6],
    categoryNames: ['Ecommerce'],
    website: 'https://woocommerce.com',
    js: [{ property: 'wc_add_to_cart_params', pattern: '' }, { property: 'woocommerce_params', pattern: '' }],
    scripts: [{ pattern: 'woocommerce' }],
    implies: ['WordPress'],
  },

  // ============================================================
  // Authentication & Identity
  // ============================================================
  {
    name: 'Auth0',
    categories: [69],
    categoryNames: ['Authentication'],
    website: 'https://auth0.com',
    js: [{ property: 'auth0', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.auth0\\.com' }],
  },
  {
    name: 'Firebase',
    categories: [34],
    categoryNames: ['Databases'],
    website: 'https://firebase.google.com',
    js: [{ property: 'firebase', pattern: '' }],
    scripts: [{ pattern: 'firebasejs/' }, { pattern: 'firebase-app\\.js' }],
  },
  {
    name: 'Supabase',
    categories: [34],
    categoryNames: ['Databases'],
    website: 'https://supabase.com',
    js: [{ property: 'supabase', pattern: '' }],
    scripts: [{ pattern: 'supabase' }],
  },

  // ============================================================
  // UI & Component Libraries
  // ============================================================
  {
    name: 'Bootstrap',
    categories: [66],
    categoryNames: ['UI frameworks'],
    website: 'https://getbootstrap.com',
    cpe: 'cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*',
    js: [{ property: 'bootstrap', pattern: '' }],
    dom: [{ selector: 'link[href*="bootstrap"]', check: { type: 'exists' } }],
    scripts: [{ pattern: 'bootstrap(?:\\.bundle)?(?:\\.min)?\\.js' }],
  },
  {
    name: 'Tailwind CSS',
    categories: [66],
    categoryNames: ['UI frameworks'],
    website: 'https://tailwindcss.com',
    dom: [{ selector: 'link[href*="tailwind"]', check: { type: 'exists' } }],
    scripts: [{ pattern: 'tailwindcss' }, { pattern: 'cdn\\.tailwindcss\\.com' }],
  },
  {
    name: 'Material UI',
    categories: [66],
    categoryNames: ['UI frameworks'],
    website: 'https://mui.com',
    dom: [
      { selector: '.MuiButton-root', check: { type: 'exists' } },
      { selector: '[class*="makeStyles-"]', check: { type: 'exists' } },
    ],
    implies: ['React'],
  },

  // ============================================================
  // Error Tracking & Monitoring
  // ============================================================
  {
    name: 'Sentry',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://sentry.io',
    js: [{ property: 'Sentry', pattern: '' }, { property: '__SENTRY__', pattern: '' }],
    scripts: [{ pattern: 'browser\\.sentry-cdn\\.com' }, { pattern: 'sentry\\.io' }],
  },
  {
    name: 'Datadog RUM',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://www.datadoghq.com',
    js: [{ property: 'DD_RUM', pattern: '' }],
    scripts: [{ pattern: 'datadoghq\\.com' }],
  },
  {
    name: 'New Relic',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://newrelic.com',
    js: [{ property: 'NREUM', pattern: '' }, { property: 'newrelic', pattern: '' }],
    scripts: [{ pattern: 'js-agent\\.newrelic\\.com' }],
  },
  {
    name: 'LogRocket',
    categories: [10],
    categoryNames: ['Analytics'],
    website: 'https://logrocket.com',
    js: [{ property: 'LogRocket', pattern: '' }, { property: '_lr_loaded', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.logrocket\\.com' }, { pattern: 'cdn\\.lr-ingest\\.io' }],
  },

  // ============================================================
  // Chat & Support
  // ============================================================
  {
    name: 'Intercom',
    categories: [52],
    categoryNames: ['Live chat'],
    website: 'https://www.intercom.com',
    js: [{ property: 'Intercom', pattern: '' }],
    dom: [{ selector: '#intercom-container', check: { type: 'exists' } }],
    scripts: [{ pattern: 'widget\\.intercom\\.io' }],
  },
  {
    name: 'Zendesk',
    categories: [52],
    categoryNames: ['Live chat'],
    website: 'https://www.zendesk.com',
    js: [{ property: 'zE', pattern: '' }, { property: 'Zendesk', pattern: '' }],
    scripts: [{ pattern: 'static\\.zdassets\\.com' }],
  },
  {
    name: 'Crisp',
    categories: [52],
    categoryNames: ['Live chat'],
    website: 'https://crisp.chat',
    js: [{ property: '$crisp', pattern: '' }, { property: 'CRISP_WEBSITE_ID', pattern: '' }],
    scripts: [{ pattern: 'client\\.crisp\\.chat' }],
  },
  {
    name: 'Drift',
    categories: [52],
    categoryNames: ['Live chat'],
    website: 'https://www.drift.com',
    js: [{ property: 'drift', pattern: '' }, { property: 'driftt', pattern: '' }],
    scripts: [{ pattern: 'js\\.driftt\\.com' }],
  },
  {
    name: 'Tawk.to',
    categories: [52],
    categoryNames: ['Live chat'],
    website: 'https://www.tawk.to',
    js: [{ property: 'Tawk_API', pattern: '' }],
    scripts: [{ pattern: 'embed\\.tawk\\.to' }],
  },
  {
    name: 'HubSpot',
    categories: [32],
    categoryNames: ['Marketing automation'],
    website: 'https://www.hubspot.com',
    js: [{ property: '_hsq', pattern: '' }, { property: 'HubSpotConversations', pattern: '' }],
    scripts: [{ pattern: 'js\\.hs-scripts\\.com' }, { pattern: 'js\\.hsforms\\.net' }],
  },

  // ============================================================
  // Cookie Consent & Privacy
  // ============================================================
  {
    name: 'Cookiebot',
    categories: [67],
    categoryNames: ['Cookie compliance'],
    website: 'https://www.cookiebot.com',
    js: [{ property: 'Cookiebot', pattern: '' }, { property: 'CookieConsent', pattern: '' }],
    scripts: [{ pattern: 'consent\\.cookiebot\\.com' }],
  },
  {
    name: 'OneTrust',
    categories: [67],
    categoryNames: ['Cookie compliance'],
    website: 'https://www.onetrust.com',
    js: [{ property: 'OneTrust', pattern: '' }, { property: 'OptanonWrapper', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.cookielaw\\.org' }],
  },

  // ============================================================
  // CDN & Performance
  // ============================================================
  {
    name: 'Cloudflare',
    categories: [31],
    categoryNames: ['CDN'],
    website: 'https://www.cloudflare.com',
    js: [{ property: '__cf_bm', pattern: '' }],
    scripts: [{ pattern: 'cdnjs\\.cloudflare\\.com' }],
  },
  {
    name: 'Vercel',
    categories: [62],
    categoryNames: ['PaaS'],
    website: 'https://vercel.com',
    js: [{ property: '__NEXT_DATA__', pattern: '' }],
    dom: [
      { selector: 'script[src*="vercel"]', check: { type: 'exists' } },
    ],
  },
  {
    name: 'Netlify',
    categories: [62],
    categoryNames: ['PaaS'],
    website: 'https://www.netlify.com',
    scripts: [{ pattern: 'netlify' }],
  },

  // ============================================================
  // Payment
  // ============================================================
  {
    name: 'Stripe',
    categories: [41],
    categoryNames: ['Payment processors'],
    website: 'https://stripe.com',
    js: [{ property: 'Stripe', pattern: '' }],
    scripts: [{ pattern: 'js\\.stripe\\.com' }],
  },
  {
    name: 'PayPal',
    categories: [41],
    categoryNames: ['Payment processors'],
    website: 'https://www.paypal.com',
    js: [{ property: 'paypal', pattern: '' }],
    scripts: [{ pattern: 'paypal\\.com/sdk/js' }, { pattern: 'paypalobjects\\.com' }],
  },

  // ============================================================
  // A/B Testing & Feature Flags
  // ============================================================
  {
    name: 'Optimizely',
    categories: [74],
    categoryNames: ['A/B testing'],
    website: 'https://www.optimizely.com',
    js: [{ property: 'optimizely', pattern: '' }],
    scripts: [{ pattern: 'cdn\\.optimizely\\.com' }],
  },
  {
    name: 'LaunchDarkly',
    categories: [74],
    categoryNames: ['A/B testing'],
    website: 'https://launchdarkly.com',
    js: [{ property: 'LDClient', pattern: '' }],
    scripts: [{ pattern: 'app\\.launchdarkly\\.com' }],
  },

  // ============================================================
  // Build Tools / Bundlers (detectable at runtime)
  // ============================================================
  {
    name: 'Webpack',
    categories: [19],
    categoryNames: ['Miscellaneous'],
    website: 'https://webpack.js.org',
    js: [{ property: 'webpackJsonp', pattern: '' }, { property: 'webpackChunk', pattern: '' }],
  },
  {
    name: 'Vite',
    categories: [19],
    categoryNames: ['Miscellaneous'],
    website: 'https://vitejs.dev',
    dom: [
      { selector: 'script[type="module"][src*="/@vite"]', check: { type: 'exists' } },
      { selector: 'script[type="module"][src*="/.vite"]', check: { type: 'exists' } },
    ],
  },

  // ============================================================
  // Implied-only technologies (no JS checks, resolved via implies)
  // ============================================================
  { name: 'PHP', categories: [27], categoryNames: ['Programming languages'], website: 'https://www.php.net' },
  { name: 'MySQL', categories: [34], categoryNames: ['Databases'], website: 'https://www.mysql.com' },
  { name: 'Node.js', categories: [27], categoryNames: ['Programming languages'], website: 'https://nodejs.org' },
];
