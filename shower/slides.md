# read_req()

~~~~~{.c}
void read_req(void) {
  char buf[128];
  int i;
  gets(buf);
  i = atoi(buf);
}
~~~~~

# Exploit (if stack grows down)

<pre><code style="line-height:0.8;font-family: monospace;">
    0x00
      ^         ....
      |  +------------------+ <- esp
         |   return addr.   |
         +------------------+
         |      &buf        |
         +------------------+
         |        i         |
         +------------------+            +----------+<--+
         |     buf[0:3]     |            | shell    |   |
         |      ...         |            | code     |   |
         +------------------+ <- ebp     |          |   |
         |    saved ebp     |            |          |   |
         +------------------+            |          |   |
         |   return addr    |            |//////////|---+
         +------------------+            +----------+
</code></pre>

# Exploit (if stack grows up)

 - Can't overwrite the return addr (of read_req)?

<pre><code style="line-height:0.8;font-family: monospace;">
      0x00
         +------------------+
         |   return addr.   |
         +------------------+
         |    saved ebp     |
         +------------------+            +----------+
         |     buf[0:3]     |            | shell    |
         |      ...         |            | code     |
         +------------------+            |          |
         |        i         |            |          |
       | +------------------+            +----------+
       v        ...
</code></pre>

# Exploit (if stack grows up)

<pre><code style="line-height:0.8;font-family: monospace;">
      0x00
         +------------------+
         |   return addr.   |
         +------------------+
         |    saved ebp     |
         +------------------+ <---+      +----------+<--+
         |     buf[0:3]     |     |      | shell    |   |
         |      ...         |     |      | code     |   |
         +------------------+     |      |          |   |
         |        i         |     |      |          |   |
         +------------------+     |      |          |   |
         |      &buf        | ----+      |          |   |
         +------------------+            |          |   |
         |   return addr.   |            |//////////|---+
         +------------------+            +----------+
         |    saved ebp     |
       | +------------------+
       v        ...
</code></pre>

# Heartbleed (CVE-2014-0160)
 - OpenSSL: popular SSL/TLS library
 - Heartbeat: keep connections alive even if no data to be transmitted
 - Send <-> response (identical copy of the payload)

~~~~~{.c}
struct Msg {
  u8    type;      /* 1 bytes */
  u16   length;    /* 2 bytes */
  char* payload;   /* len(payload) = length */
  char* padding[]; /* minimum: 16 */
};
~~~~~

# Code (@ssl/d1_both.c)

~~~~~{.c}
// Msg = [type][len][payload][padding]
type = *p++;     // p = Msg
n2s(p, length);  // length = p.length
payload = p;     // payload = p.payload

if (type == TLS1_HB_REQUEST) {
  unsigned char *buf, *bp;
  
  buf = OPENSSL_malloc(1 + 2 + length + padding);
  bp = buf;
~~~~~

# Code (@ssl/d1_both.c)

~~~~~{.c}
  // bp = Msg (type/length)
  *bp++ = TLS1_HB_RESPONSE;
  s2n(length, bp);

  // copy payload to the buffer
  memcpy(bp, payload, length);
  ssl3_write_bytes(s, TLS1_RT_HEARTBEAT,
                    buf, 1 + 2 + length + padding);
~~~~~

# {.cover .w}
 ![](xkcd.png) 

# Consequences
 - Dump upto 64KB of memory
 - It might contain sensitive data
   (e.g., secrete key, passwd &c)
 - What should we do?

# Fixes (@ssl/d1_both.c)

~~~~~{.c}
/* discard zero-size heartbeat */
if (1 + 2 + 16 > s->s3->rrec.length)
    return 0;
    
type = *p++;
n2s(p, payload);

/* discard if it lies */
if (1 + 2 + payload + 16 > s->s3->rrec.length)
    return 0;
~~~~~

# Lessons
 - A naive mistake can destroy the entire trust chains
 - Don't write own parser?
 - Don't use C?

# CS101: quiz <br> (by John Regehr) {.shout}


# Q1. What does the expression 1 > 0 evaluate to?
1. 0
1. 1
1. undefined

# Q2. 1U > -1?
1. 0
1. 1
1. undefined

<footer>
- unsigned wins (-1 promotes to UINT_MAX)
- unsigned int > unsigned int
- warning from gcc
- don't mix
</footer>

# Q3. (unsigned short)1 > -1?
1. 0
1. 1
1. undefined

<footer>
- int > int
- if not losing values -> unsigned short promotes to int
- Q2: unsigned int can not be promoted to int since it would change
  large values into negatives
</footer>

# Q4. -1L > 1U? on x86-64? on x86?
1. 0 on both platforms
1. 1 on both platforms
1. 0 on x86-64, 1 on x86
1. 1 on x86-64, 0 on x86

<footer>
- x86-64: unsigned int -> long  (1U -> 1L)
- x86: long -> unsigned int (-1L -> UINT_MAX)
</footer>

# Q5. SCHAR_MAX == CHAR_MAX?
1. 0
1. 1
1. undefined

<footer>
- signedness of the char is implementation-defined
- CHAR is signed in x86/x86-64
</footer>

# Q6. UINT_MAX + 1?
1. 0
1. 1
1. INT_MAX
1. UINT_MAX
1. undefined

<footer>
- standards: wrap unsigned int
</footer>

# Q7. INT_MAX + 1?
1. 0
1. 1
1. INT_MAX
1. UINT_MAX
1. INT_MIN
1. undefined

<footer>
- standards: overflowing int is undefined
</footer>

# Q8. -INT_MIN?
1. 0
1. 1
1. INT_MAX
1. UINT_MAX
1. INT_MIN
1. undefined

<footer>
- no way to represent the inverse of INT_MIN
</footer>

# Q9. Assume x has type int. Is the expression x<<0...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- a negative value cannot be left-shifted
</footer>

# Q10. Assume x has type int. Is the expression x<<1...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- shifting a 1 into the sign bit is an error
- INT_MAX << 1 is undefined
</footer>

# Q11. Assume x has type int. Is the expression x<<31...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- 0 is the only one
</footer>

# Q12. Assume x has type int. Is the expression x<<32...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- exceeding bitwidth
</footer>

# Q13. Assume x has type short. Is the expression x<<29...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- promoted to int, then applies the above rules
</footer>

# Q14. Assume x has type unsigned. Is the expression x<<31...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- if less than width of the unsigned type
</footer>

# Q15. Assume x has type unsigned short. Is the expression x<<31...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- unsigned short -> int, touch sign bit
</footer>

# Q16. Assume x has type int. Is the expression x + 1...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- no for INT_MAX
</footer>

# Q17. Assume x has type int. Is the expression x - 1 + 1...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- no for INT_MIN
</footer>

# Q18. Assume x has type int. Is the expression (short)x + 1...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- safe for all
</footer>

# Q19. Assume x has type int. Is the expression (short)(x + 1)...
1. defined for all values of x
1. defined for some values of x
1. defined for no values of x

<footer>
- no for INT_MAX
</footer>

# kint {.shout}

# Q1

- First, ignoring range metadata, what constraint would KINT generate
  for the count variable in the code from Figure 3?

<div class=next>
~~~~~{.c}
count > [(ULONG_MAX - sizeof(struct rps_dev_flow_table)) \
            / sizeof(struct rps_dev_flow)]
AND
count <= 1 << 30
~~~~~
</div>

# Q2.

- How can you simplify the snippet of code in Figure 1 using the NaN
  integers as described in Section 7?

<div class=next>
~~~~~{.c}
nan size_t page_count
nan size_t page_total = pg_start + page_count
  
if (isnan(pg_total) || (pg_total > num_entries))
    return EINVAL;
~~~~~
</div>