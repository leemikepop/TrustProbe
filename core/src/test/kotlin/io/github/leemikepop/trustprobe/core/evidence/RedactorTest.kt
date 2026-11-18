package io.github.leemikepop.trustprobe.core.evidence

import org.junit.Assert.assertEquals
import org.junit.Test

class RedactorTest {
    @Test
    fun redactsLongValue() {
        assertEquals("Bear…", Redactor.value("Bearer eyJhbGciOi"))
    }

    @Test
    fun shortValuesAreFullyMasked() {
        assertEquals("…", Redactor.value("abc"))
        assertEquals("…", Redactor.value(""))
        assertEquals("密碼一二…", Redactor.value("密碼一二三四五"))
    }

    @Test
    fun doesNotSplitSurrogatePairs() {
        assertEquals("😀😀😀😀…", Redactor.value("😀😀😀😀😀"))
        assertEquals("…", Redactor.value("😀😀😀😀"))
    }

    @Test
    fun redactsQueryValues() {
        assertEquals("/a?token=abcd…&x=…", Redactor.path("/a?token=abcdefgh&x=1"))
    }

    @Test
    fun masksBareQueryPartAndDropsFragment() {
        assertEquals("/a?…&k=abcd…", Redactor.path("/a?flag&k=abcdefgh#secret"))
        assertEquals("/a", Redactor.path("/a#frag"))
    }

    @Test
    fun reducesAbsoluteFormTarget() {
        assertEquals("/p?x=…", Redactor.path("https://h.example.com/p?x=1"))
        assertEquals("/", Redactor.path("http://h.example.com"))
    }
}
