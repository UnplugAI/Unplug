/*
 * Adapted from NVIDIA NeMo Guardrails (Apache-2.0).
 * Markdown / HTML XSS markers in untrusted content.
 */
rule markdown_xss
{
    meta:
        description = "Detect potential cross-site scripting in Markdown"

    strings:
        $html_link = "href"
        $js = "javascript"
        $re_script = /<script>[^\n]+?<\x2Fscript>/i
        $re_md_embed = /\s?!\[[^\n]+\]\([^\n]+\)/
        $re_md_js = /\[[^\n]+\]\(javascript[\^n]+\)/

    condition:
        any of ($re*) or (@html_link < @js)
}
