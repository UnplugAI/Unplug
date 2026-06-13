/*
 * Adapted from NVIDIA NeMo Guardrails (Apache-2.0).
 * Multi-token SQL injection heuristics: tightened to avoid natural-language FPs
 * (e.g. contractions like "you're" must not match).
 */
rule sql_injection
{
    meta:
        description = "Detect possible SQL injection attempts"

    strings:
        $drop_table = /\bDROP\b\s+TABLE\b/i
        $union_select = /\bUNION\b[\s\S]{0,40}\bSELECT\b/i
        $exec_sp = /\bEXEC\b\s*\(/i
        $quote_or = /'\s*OR\b/i
        $quote_comment = /'\s*--/
        $semicolon_sql = /;\s*(DROP|DELETE|UPDATE|INSERT|SELECT|ALTER|CREATE|TRUNCATE)\b/i

        $sql_kw = /\b(SELECT|ALTER|CREATE|INSERT|DELETE|TRUNCATE|EXEC|UNION|DROP)\b/i
        $dash_comment = /--[^\r\n]+/
        $semicolon_tail = /;[^\r\n]+/
        $char_obfuscation = /(cha?r\(\d+\)([,+]|\|\|)?)+/i
        $system_catalog = /\b(SELECT|FROM)\s+pg_\w+/i

    condition:
        any of ($drop_table, $union_select, $exec_sp, $quote_or, $quote_comment, $semicolon_sql)
        or (1 of ($sql_kw) and 1 of ($dash_comment, $semicolon_tail, $char_obfuscation, $system_catalog))
}
