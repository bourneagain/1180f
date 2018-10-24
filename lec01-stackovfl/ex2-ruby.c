/* CVE-2014-4975 */
/*  ref. https://svn.ruby-lang.org/cgi-bin/viewvc.cgi/trunk/pack.c?r1=45921&r2=46778 */

/* @pack.c
    ["a"*3070].pack("m4000")
      => encode(var, "aaa..", 3070, .., true) */
static void
encodes(VALUE str, const char *s, long len, int type, int tail_lf) {
    char buff[4096];
    long i = 0;
    const char *trans = type == 'u' ? uu_table : b64_table;
    char padding;

    if (type == 'u') {
        buff[i++] = (char)len + ' ';
        padding = '`';
    }
    else {
        padding = '=';
    }
    while (len >= 3) {
        while (len >= 3 && sizeof(buff)-i >= 4) {
            buff[i++] = trans[077 & (*s >> 2)];
            buff[i++] = trans[077 & (((*s << 4) & 060) | ((s[1] >> 4) & 017))];
            buff[i++] = trans[077 & (((s[1] << 2) & 074) | ((s[2] >> 6) & 03))];
            buff[i++] = trans[077 & s[2]];
            s += 3;
            len -= 3;
        }
        if (sizeof(buff)-i < 4) {
            rb_str_buf_cat(str, buff, i);
            i = 0;
        }
    }

    if (len == 2) {
        buff[i++] = trans[077 & (*s >> 2)];
        buff[i++] = trans[077 & (((*s << 4) & 060) | ((s[1] >> 4) & 017))];
        buff[i++] = trans[077 & (((s[1] << 2) & 074) | (('\0' >> 6) & 03))];
        buff[i++] = padding;
    }
    else if (len == 1) {
        buff[i++] = trans[077 & (*s >> 2)];
        buff[i++] = trans[077 & (((*s << 4) & 060) | (('\0' >> 4) & 017))];
        buff[i++] = padding;
        buff[i++] = padding;
    }
    if (tail_lf) buff[i++] = '\n';
    rb_str_buf_cat(str, buff, i);
}