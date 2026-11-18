package io.github.leemikepop.trustprobe.core.evidence

/** Masks header and query values so reports never carry secrets. */
object Redactor {
    private const val PREVIEW_CODE_POINTS = 4
    private const val ELLIPSIS = "…"

    /** First 4 Unicode code points plus an ellipsis; values of 4 or fewer code points become just the ellipsis. */
    fun value(v: String): String {
        if (v.codePointCount(0, v.length) <= PREVIEW_CODE_POINTS) return ELLIPSIS
        val end = v.offsetByCodePoints(0, PREVIEW_CODE_POINTS)
        return v.substring(0, end) + ELLIPSIS
    }

    /** Keeps path and query keys, masks query values, drops the fragment and any scheme/authority. */
    fun path(p: String): String {
        var target = p.substringBefore('#')
        val schemeEnd = target.indexOf("://")
        if (schemeEnd > 0 && target.substring(0, schemeEnd).all { it.isLetterOrDigit() || it in "+-." }) {
            val pathStart = target.indexOf('/', schemeEnd + 3).let { s ->
                val q = target.indexOf('?', schemeEnd + 3)
                if (s == -1 || (q != -1 && q < s)) -1 else s
            }
            target = when {
                pathStart != -1 -> target.substring(pathStart)
                target.indexOf('?', schemeEnd + 3) != -1 -> "/" + target.substring(target.indexOf('?', schemeEnd + 3))
                else -> "/"
            }
        }
        val q = target.indexOf('?')
        if (q == -1) return target
        val query = target.substring(q + 1).split('&').joinToString("&") { part ->
            val eq = part.indexOf('=')
            if (eq == -1) value(part) else part.substring(0, eq + 1) + value(part.substring(eq + 1))
        }
        return target.substring(0, q + 1) + query
    }
}
