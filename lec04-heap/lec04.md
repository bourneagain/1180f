@title(Lec04: Heap-related Vulnerabilities, Taesoo Kim)

# Goals and Lessons
- Learn about the heap-related vulnerabilities
    - Buffer overflow/underflow, out-of-bound read
    - Use-after-free, including double frees
- Understand their security implications
- Understand the off-the-shelf mitigation (lec05)
- Learn them from the real-world examples

# Classifying Heap Vulnerabilities
- Buffer overflow/underflow, out-of-bound read
    - Much prevalent (i.e., quality, complexity)
    - Much critical (i.e., larger attack surface)
- Heap-specific issues
    - Use-after-free (e.g., dangled pointers)
    - Incorrect uses (e.g., double frees)

# Simple High-level Interfaces

~~~~{.c}
  void *malloc(size_t size);
  void free(void *ptr);
  void *calloc(size_t nmemb, size_t size);
  void *realloc(void *ptr, size_t size);
~~~~

# CS101: Heap Allocators

~~~~{.c}
Q1. malloc(0)    = ?
Q2. malloc(-1)   = ?
Q3. XXX.
~~~~

# Understanding Modern Heap Allocators

 @img(w150%, img/heap.svg)

# Exercises: Real-world Examples

- CVE-2014-0160: OpenSSL
- CVE-2018-11360: Wireshark
- CVE-2016-0728: Linux vmacache (refcnt)

# Example of Use-after-free

 @img(w40%, img/ex0.svg)

~~~{.cc .numberLines}
class Div: Element;
class Body: Element;
class Document { Element* child; };
~~~

# Example of Use-after-free

 @img(w60%, img/ex1.svg)

~~~{.cc .numberLines}
class Div: Element;
class Body: Element;
class Document { Element* child; };

// (a) memory allocations
Document *doc = new Document();
Body *body = new Body();
Div *div = new Div();
~~~

# Example of Use-after-free

 @img(w60%, img/ex2.svg)

~~~{.cc .numberLines}
// (b) using memory: propagating pointers
doc->child = body;
body->child = div;

// (c) memory free: doc->child is now dangled
delete body;

// (d) use-after-free: dereference the dangled pointer
if (doc->child)
    doc->child->getAlign();
~~~~

# Exercise: Real-world Examples
- Ex1. OpenSSL (CVE-2014-0160)
- Ex2. Wireshark (CVE-2018-11360)
- Ex3. Linux vmcache (CVE-2018-17182)

# CVE-2014-0160: OpenSSL, Heartbleed
- Information leakage (i.e., private keys)

 @img(w60%, img/xkcd-heartbleed.png)

Ref. <https://xkcd.com/1354/>

# CVE-2014-0160: OpenSSL, Heartbleed
- "Heartbeat" messages to ensure the connection is alive

~~~~
                  |<---  len''  --->|
-> req: [REQ][len'][payload ....    ]
<- res: [RES][len'][payload ....    ][padding]

  len' != len''
  what if len' >> len''?
~~~~

# CVE-2014-0160: OpenSSL, Heartbleed

~~~~{.c .numberLines}
  /* Read type and payload length first */
  hbtype = *p++;
  n2s(p, payload);
  pl = p;

  if (hbtype == TLS1_HB_REQUEST) {
    bp = OPENSSL_malloc(1 + 2 + payload + padding);

    /* Enter response type, length and copy payload */
    *bp++ = TLS1_HB_RESPONSE;
    s2n(payload, bp);
    memcpy(bp, pl, payload);
~~~~

# CVE-2014-0160: OpenSSL, Heartbleed

~~~~{.c .numberLines}
   unsigned int payload;
   ...
+  /* Read type and payload length first */
+  if (1 + 2 + 16 > s->s3->rrec.length)
+    return 0; /* silently discard */
+
+  hbtype = *p++;
+  n2s(p, payload);
+  if (1 + 2 + payload + 16 > s->s3->rrec.length) // BUG?
+    return 0; /* silently discard per RFC 6520 sec. 4 */
+  pl = p;
+
   if (hbtype == TLS1_HB_REQUEST) { ... }
~~~~

# CVE-2018-11360: Wireshark

~~~~{.c .numberLines}
void IA5_7BIT_decode(unsigned char *dest, 
                     const unsigned char *src, int len) {
  int i, j;
  gunichar buf;

  for (i = 0, j = 0; j < len;  j++) {
    buf = char_def_ia5_alphabet_decode(src[j]);
    i += g_unichar_to_utf8(buf,&(dest[i]));
  }
  dest[i]=0;
  return;
}
~~~~


# References

- [CVE-2018-17182](https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html)
- [Vudo - An object superstitiously believed to embody magical powers](http://phrack.org/issues/57/8.html)