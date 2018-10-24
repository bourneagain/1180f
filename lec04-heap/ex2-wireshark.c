/* CVE-2018-11360
   ref. https://code.wireshark.org, @47a5fa850b388fcf4ea762073806f01b459820fe */

static guint16
de_sub_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset,
            guint len, gchar **extracted_address){
  ...
  ia5_string = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb,
                                    curr_offset, ia5_string_len);
  *extracted_address = (gchar *)wmem_alloc(wmem_packet_scope(), ia5_string_len);
 
  invalid_ia5_char = FALSE;
  for(i = 0; i < ia5_string_len; i++) {
    dig1 = (ia5_string[i] & 0xf0) >> 4;
    dig2 = ia5_string[i] & 0x0f;
    oct = (dig1 * 10) + dig2 + 32;
    if (oct > 127)
      invalid_ia5_char = TRUE;
    ia5_string[i] = oct;
  }
 
  IA5_7BIT_decode(*extracted_address, ia5_string, ia5_string_len);
  ...
}

void
IA5_7BIT_decode(unsigned char *dest, const unsigned char *src, int len) {
  int i, j;
  gunichar buf;

  for (i = 0, j = 0; j < len;  j++) {
    buf = char_def_ia5_alphabet_decode(src[j]);
    i += g_unichar_to_utf8(buf,&(dest[i]));
  }
  dest[i]=0;
  return;
}