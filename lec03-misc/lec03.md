@title(Lec03: Integer overflow, race conditions, and uninitialized reads, Taesoo Kim)

<style>
 #cover h2 { font-size: 50px !important; margin-bottom: 1.5em !important; }
</style>

# Goals and Lessons
- Learn about three classes of vulnerabilities
    1. Integer overflow (undefined behavior)
    1. Race condition
    1. Uninitialized reads
- Understand their security implications
- Understand the off-the-shelf mitigation
- Learn them from the real-world examples

# Basic Idea: Integer Representation

XXX. (from phrack)

# Integer Overflow Real Life Impacts

- 1996: Ariane 5 rocket crashed
- 2015: FAA requested to reset Boeing 787 every 248 days
- 2016: a Casino machine printed a prize ticket of $42,949,672!

# CS101: Int. Ovfl. and Undefined Behavior

- (in 64-bit) what does the expression, 1 > 0, evaluate to?
    - ? (a) 0, (b) 1, (c) NaN, (d) -1
;  > b
- (unsigned short)1 > -1?
    - ? (a) 1, (b) 0, (c) -1, (d) undefined
;  > a
- -1U > 0?
    - ? (a) 1, (b) 0, (c) -1, (d) undefined
;  > a

# Q.
- -1L > 1U? on x86-64 and x86
    - ? (a) 0 on both platforms, (b) 1 on both platforms, (c) 0 on x86-64, 1 on x86, (d) 1 on x86-64, 0 on x86
;  > c
- UINT_MAX + 1?
    - ? (a) 0, (b) 1, (c) INT_MAX, (d) UINT_MAX, (e) undefined
;  > a
- (in 32-bit) what's abs(-2147483648)?
    - ? (a) == 0, (b) < 0, (c) > 0, (d) == NaN
;  > b

# Discussion: intq
- -1 << 2?
    - ? (a) 0, (b) 4, (c) INT_MAX, (d) INT_MIN, (e) undefined
;  > e
- INT_MAX + 1?
    - ? (a) 0, (b) 1, (c) INT_MAX, (d) UINT_MAX, (e) undefined
;  > e
- -INT_MIN?
    - ? (a) 0, (b) 1, (c) INT_MAX, (d) UINT_MAX, (e) INT_MIN, (f) undefined
;  > f

# Secure Way to Add Two Ints

- [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow)

~~~~{.c}
void func(signed int si_a, signed int si_b) {
  signed int sum = si_a + si_b;
  /* ... */
}
~~~~

# Secure Way to Add Two Ints

~~~~{.c .numberLines}
#include <limits.h>
  
void f(signed int si_a, signed int si_b) {
  signed int sum;
  if (((si_b > 0) && (si_a > (INT_MAX - si_b))) ||
      ((si_b < 0) && (si_a < (INT_MIN - si_b)))) {
    /* Handle error */
  } else {
    sum = si_a + si_b;
  }
  /* ... */
}
~~~~

# Secure Way to Multiplying Two Ints

~~~~{.c}
void func(signed int si_a, signed int si_b) {
  signed int result = si_a * si_b;
  /* ... */
}
~~~~

# Secure Way to Multiplying Two Ints
~~~~{.c .numberLines}
void func(signed int si_a, signed int si_b) {
  signed int result;
  signed long long tmp;

  tmp = (signed long long)si_a * (signed long long)si_b;
  
  /* If the product cannot be represented as a 32-bit integer,
     handle as an error condition. */
  if ((tmp > INT_MAX) || (tmp < INT_MIN)) {
    /* Handle error */
  } else {
    result = (int)tmp;
  }
  /* ... */
}
~~~~

# Secure Way to Multiplying Two Ints

 @img(w60%, img/mult.png)

# Case Study: Chackra Core (Multiplying Ints)

~~~~{.c .numberLines}
// Returns true if we overflowed, false if we didn't
bool Int64Math::Mul(int64 left, int64 right, int64 *pResult) {
#if defined(_M_X64) 
  // (I)MUL (Q/64) R[D/A]X <- RAX * r/m64
  int64 high;
  *pResult = _mul128(left, right, &high);
  return ((*pResult > 0) && high != 0) \
           || ((*pResult < 0) && (high != -1));
#else
  *pResult = left * right;
  return (left != 0 && right != 0 \
           && (*pResult / left) != right);
#endif
}
~~~~

# Case Study: glibc (Multiplying UInts)

~~~~{.c .numberLines}
static inline bool
check_mul_overflow_size_t(size_t left, size_t right, 
                          size_t *result) {
  /* size_t is unsigned 
     so the behavior on overflow is defined. */
  *result = left * right;
  size_t half_size_t \
    = ((size_t) 1) << (8 * sizeof (size_t) / 2);

  if ((left | right) >= half_size_t) {
    if (right != 0 && *result / right != left)
      return true;
  }
  return false;
}
~~~~

; Defense N
# New Proposals: __builtin_*_overflow()

- Ref. <https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html>

~~~~{.c}
bool __builtin_add_overflow (type1 a, type2 b, type3 *res);
bool __builtin_sub_overflow (type1 a, type2 b, type3 *res);
bool __builtin_mul_overflow (type1 a, type2 b, type3 *res);

bool __builtin_uadd_overflow (unsigned int a, unsigned int b,
                              unsigned int *res);
...
~~~~

# Example: New calloc()

~~~~{.c .numberLines}
void * calloc (size_t x, size_t y) {
  size_t sz;
  if (__builtin_mul_overflow (x, y, &sz))
    return NULL;
  void *ret = malloc (sz);
  if (ret)
    memset (ret, 0, sz);
  return ret;
}
~~~~

# Undefined Behaviors and Optimization

- ref. https://kristerw.blogspot.com/2016/02/how-undefined-signed-overflow-enables.html
- ref. https://nullprogram.com/blog/2018/07/20/
- -fwrapv
- -fno-strict-aliasing

# Double Fetching Vulnerabilities
- A special form of race conditions: user vs. kernel spaces
- Leading to information leaks, buffer overflows, etc.

 @img(w95%, img/doublefetch.png)

# Example: perf_copy_attr() Explained
 @img(w90%, img/doublefetch1.png)

# Example: perf_copy_attr() Explained
 @img(w90%, img/doublefetch2.png)

# Example: perf_copy_attr() Explained
 @img(w90%, img/doublefetch3.png)

# BUG: Racing in Userspace
 @img(w90%, img/doublefetch5.png)

# BUG: "Double" Fetching from Kernel
 @img(w90%, img/doublefetch6.png)

# BUG: Trigger Incorrect Memory Copy
 @img(w90%, img/doublefetch7.png)

# Fixing Double Fetches
- Partialy reading after the size attribute
- Ensuring the atomicity of previous checked size

~~~~{.c .numberLines}
  // @f12f42acdbb577a12eecfcebbbec41c81505c4dc
  ret = get_user(size, &uattr->size);
  ret = copy_from_user(attr, uattr, size);
  ...

  // overwrite with the sanitiy-checked size
+ attr->size = size; 
~~~~

# CVE-2009-3234: Buffer Overflow!

~~~~{.c .numberLines}
  /* If we're handed a bigger struct than we know of,
   * ensure all the unknown bits are 0.	 */
  if (size > sizeof(*attr)) {
    ...
    for (; addr < end; addr += sizeof(unsigned long)) {
      ret = get_user(val, addr);
      if (ret)
        return ret;
      if (val)
        goto err_size;
    }
  }
  ret = copy_from_user(attr, uattr, size); // Q. size?
~~~~

# CVE-2009-3234: Buffer Overflow!

~~~~{.c .numberLines}
  /* If we're handed a bigger struct than we know of,
   * ensure all the unknown bits are 0.	 */
  if (size > sizeof(*attr)) {
    ...
    for (; addr < end; addr += sizeof(unsigned long)) {
      ret = get_user(val, addr);
      if (ret)
        return ret;
      if (val)
        goto err_size;
    }
+   size = sizeof(*attr);
  }
  ret = copy_from_user(attr, uattr, size); // Q. size?
~~~~

# CVE-2016-4482: Linux USB

~~~~{.c .numberLines}
static int proc_connectinfo(struct usb_dev_state *ps, 
                            void __user *arg) {
  struct usbdevfs_connectinfo ci = {
    .devnum = ps->dev->devnum,
    .slow = ps->dev->speed == USB_SPEED_LOW
  };

  if (copy_to_user(arg, &ci, sizeof(ci)))
    return -EFAULT;
  return 0;
}
~~~~

# Padding Issues in Struct

~~~~{.c}
struct usbdevfs_connectinfo {
  unsigned int devnum;  // 4 bytes
  unsigned char slow;   // 1 bytes
};

sizeof(struct usbdevfs_connectinfo) == 8

|<---------- 8B ---------->|
[devnum      ][slw][padding]
|<--  4B  -->|<1B>|<--3B-->|
~~~~

Ref. [Proactive Kernel Memory Initialization to Eliminate Data Leakages](https://taesoo.kim/pubs/2016/lu:unisan.pdf)

# Struct Padding: No Proper Way to Initialize

> §6.2.6.1/6 (C11, ISO/IEC 9899:201x)                   
> When a value is stored in an object of structure (...),
> the bytes of the object representation that correspond 
> to any padding values.

~~~~{.c}
  struct usbdevfs_connectinfo ci = {
    .devnum = ps->dev->devnum,
    .slow = ps->dev->speed == USB_SPEED_LOW
  };
~~~~

# CVE-2016-4482: Patch

~~~~{.c .numberLines}
static int proc_connectinfo(struct usb_dev_state *ps, 
                            void __user *arg) {
+	struct usbdevfs_connectinfo ci;
+
+	memset(&ci, 0, sizeof(ci));
+	ci.devnum = ps->dev->devnum;
+	ci.slow = ps->dev->speed == USB_SPEED_LOW;
    ...
}
~~~~

# Exercise: Real-world Examples
- Ex1. Android Stagefright (CVE-2015-1538, CVE-2015-3824)
- Ex2. Linux Keyring (CVE-2016-0728)
- Ex3. Linux Perf (CVE-2009-3234/+)
- Ex4. Linux USB (CVE-2016-4482)

# CVE-2015-1538: Android (Stagefright)

~~~~{.c .numberLines}
// @edd4a76eb4747bd19ed122df46fa46b452c12a0d
// CVE-2015-1538
     mTimeToSampleCount = U32_AT(&header[4]);
+    uint64_t allocSize = mTimeToSampleCount * 2 * sizeof(uint32_t);
+    if (allocSize > SIZE_MAX) {
+      return ERROR_OUT_OF_RANGE;
+    }
     mTimeToSample = new uint32_t[mTimeToSampleCount * 2];
~~~~

# CVE-2015-3824: Android (Stagefright)

~~~~{.c .numberLines}
// @463a6f807e187828442949d1924e143cf07778c6
// CVE-2015-3824
-    uint8_t *buffer = new (std::nothrow) uint8_t[size + chunk_size];
+    if (SIZE_MAX - chunk_size <= size) {
+      return ERROR_MALFORMED;
+    }
+
+    uint8_t *buffer = new uint8_t[size + chunk_size];
~~~~

# CVE-2016-0728: Linux Keyring
~~~~{.c .numberLines}
long join_session_keyring(const char *name) {
  // refcnt is incremented on "success"!
  keyring = find_keyring_by_name(name, false); 
  if (PTR_ERR(keyring) == -ENOKEY) { ... } 
  else if (IS_ERR(keyring)) { ... }
  } else if (keyring == new->session_keyring) {
    ret = 0;
    goto error2;
  }
 error2:
  mutex_unlock(&key_session_mutex);
 error:
  abort_creds(new);
  return ret;
}
~~~~

# References

- [Stagefright Bugs](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf)
- Deadline: [paper](https://taesoo.kim/pubs/2018/xu:deadline.pdf)/[slides](https://taesoo.kim/pubs/2018/xu:deadline-slides.pdf)
- Unisan: [paper](https://taesoo.kim/pubs/2016/lu:unisan.pdf)/[slides](https://taesoo.kim/pubs/2016/lu:unisan-slides.pdf)
- [Basic Integer Overflows](http://phrack.org/issues/60/10.html)
