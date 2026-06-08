/*
 * Adapted from NVIDIA NeMo Guardrails (Apache-2.0).
 * Server-side template injection markers.
 */
rule jinja_injection
{
    meta:
        description = "Detect possible server-side template injection attempts"

    strings:
        $template_open = "{{"
        $template_close = "}}"
        $open_condition = "{%"
        $close_condition = "%}"

    condition:
        ($template_open and $template_close and (@template_open < @template_close)) or
        ($open_condition and $close_condition and (@open_condition < @close_condition))
}
