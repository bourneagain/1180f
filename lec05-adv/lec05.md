@title(Lec05: Advanced Topics in Security, Taesoo Kim)

# Goals and Lessons
- Understand *modern* attack/defenses: **ROP** and **CFI**
- Understand three classes of vulnerabilities
    - **Type confusion**: e.g., bad casting in C++
    - **Race condition**: e.g., double fetching
    - **Uninitialized read**: e.g., struct padding issues
- Learn them from real-world examples (e.g., Chrome, Linux)

# Modern Exploit against DEP (NX)
- Return-oriented Programming (ROP)
- Reusing code snippets (called gadgets) instead of injecting shellcode
    - e.g., ret-to-libc: ret -> system("/bin/sh")

# Example: Stack Smashing (w/o DEP)

~~~~{.c .numberLines}
  main() {
    char buf[16];
    scanf("%s", buf);
  }
~~~~

~~~~
(top)
  [buf  ]
||[ ... ]
||[ra   ]---+ 
||[ ... ]   |
||[shell]<--+ (inject shellcode)
||[code ]
vv[ ... ]
  [     ]
 (w/o DEP)
~~~~

# Example: Stack Smashing vis Ret-to-libc

~~~~{.c .numberLines}
  main() {
    char buf[16];
    scanf("%s", buf);
  }
~~~~
~~~~
(top)
  [buf  ]       [buf  ]
||[ ... ]       [ ... ]
||[ra   ]---+   [ra   ]---> system() in libc
||[ ... ]   |   [dummy]
||[shell]<--+   [arg1 ]---> "/bin/sh"
||[code ]       [ ... ]
vv[ ... ]       [ ... ]
  [     ]       [     ]
 (w/o DEP)    (ret-to-libc)
~~~~

# Example: Stack Smashing vis Ret-to-libc

- Q. What happens when system() returns?
- Q. Is there any way to "gracefully" terminate?

~~~~
(top)
  [buf  ]
  [ ... ]
  [ra   ]---> system() in libc
  [dummy]
  [arg1 ]---> "/bin/sh"
  [ ... ]
  [ ... ]
  [     ]
(ret-to-libc)
~~~~

# Example: Stack Smashing vis Ret-to-libc

- A. "dummy" -> exit()
- A. its first argument -> 0

~~~~
(top)                             system("/bin/sh")
  [buf  ]                         exit(0)
  [ ... ]
  [ra1  ]---> system() in libc
  [ra2  ]---> exit()
  [arg1 ]---> "/bin/sh"
  [arg2 ]---> 0
  [ ... ]
  [     ]
(ret-to-libc)
~~~~

# Example: Executing Two Functions

- The return address of main() is smashed by the buffer overflow
- It returns to system() instead of the original caller

~~~~
main(): ret                    (top)
                                  [buf  ]
                                  [ ... ]
                            esp =>[ra1  ]---> system() in libc
                                  [ra2  ]---> exit()
                                  [arg1 ]---> "/bin/sh"
                                  [arg2 ]---> 0
                                  [ ... ]
                                  [     ]
                                (ret-to-libc)
~~~~

# Example: Executing Two Functions

- dummy (i.e., ptr to exit()) is now considered as caller of system()
- arg1 is the first argument of system, "/bin/sh"

~~~~
main(): ret                    (top)
system(): ..                      [buf  ]
 caller: exit()                   [ ... ]
 arg: "/bin/sh"                   [     ]
                            esp =>[ra2  ]---> exit()
                                  [arg1 ]---> "/bin/sh"
                                  [arg2 ]---> 0
                                  [ ... ]
                                  [     ]
                                (ret-to-libc)
~~~~

# Example: Executing Two Functions

- dummy (i.e., ptr to exit()) is now considered as caller of system()
- arg1 is the first argument of system, "/bin/sh"

~~~~
main(): ret                    (top)
system(): ret                     [buf  ]
                                  [ ... ]
                                  [     ]
                            esp =>[ra2  ]---> exit()
                                  [arg1 ]---> "/bin/sh"
                                  [arg2 ]---> 0
                                  [ ... ]
                                  [     ]
                                (ret-to-libc)
~~~~

# Example: Executing Two Functions

- dummy (i.e., ptr to exit()) is now considered as caller of system()
- arg1 is the first argument of system, "/bin/sh"

~~~~
main(): ret                    (top)
system(): ret                     [buf  ]
exit():                           [ ... ]
 caller: "/bin/sh" (!!)           [     ]
 arg: 0                           [ra2  ]---> exit()
                            esp =>[arg1 ]---> "/bin/sh"
                                  [arg2 ]---> 0
                                  [ ... ]
                                  [     ]
                                (ret-to-libc)
~~~~

# Example: Execution More than Two Funcs?

- Can we chain three functions in this way? No!
- ROP generalizes this approach by using 

~~~~
(top)                             system("/bin/sh")
  [buf  ]                         exit(0)
  [ ... ]
  [ra1  ]---> system() in libc
  [ra2  ]---> exit()
  [arg1 ]---> "/bin/sh"          <- "/bin/sh" vs func3?
  [arg2 ]---> 0
  [ ... ]
  [     ]
(ret-to-libc)
~~~~

# Example: ROP

- Cleaning up stacks by using pop/ret gadgets
- Chaining them in a general fashion!

~~~~
main(): ret                    (top)
system(): ret                     [buf  ]
                                  [ ... ]
                                  [     ]
                        **  esp =>[ra2  ]---> exit()
                                  [arg1 ]---> "/bin/sh"
                                  [arg2 ]---> 0
                                  [ ... ]
                                  [     ]
                                (ret-to-libc)
~~~~

# Example: ROP

- Cleaning up stacks by using pop/ret gadgets
- Chaining them in a general fashion!

~~~~
main(): ret                    (top)
system(): ret                     [buf  ]
                                  [ ... ]
                                  [     ]
                        **  esp =>[ra2  ]---> pop/ret
                                  [arg1 ]---> "/bin/sh"
                                  [ ... ]
                                  [ ... ]
                                  [     ]
                                   (ROP)
~~~~

# Example: ROP

- Cleaning up stacks by using pop/ret gadgets
- Chaining them in a general fashion!

~~~~
main(): ret                    (top)
system(): ret                     [buf  ]
pop                               [ ... ]
                                  [     ]
                                  [     ]
                            esp =>[arg1 ]---> "/bin/sh"
                                  [ ra  ]---> exit()
                                  [ ... ]
                                  [arg2 ]---> 0
                                   (ROP)
~~~~

# Example: ROP

- Cleaning up stacks by using pop/ret gadgets
- Chaining them in a general fashion!

~~~~
main(): ret                    (top)
system(): ret                     [buf  ]
pop                               [ ... ]
ret                               [     ]
                                  [     ]
                                  [     ]
                            esp =>[ ra  ]---> exit()
                                  [ ... ]
                                  [arg2 ]---> 0
                                   (ROP)
~~~~

# Example: Beyond Two Functions!
- Cleaning up stacks by using pop/ret gadgets
- Chaining them in a general fashion!

~~~~
(top)                             system("/bin/sh")
  [buf  ]                         exit(0)
  [ ... ]                         func3(arg3, arg4)
  [ra1  ]---> system() in libc | 
* [gadgt]---> pop/ret          | system() 
  [arg1 ]---> "/bin/sh"        |
  [ra2  ]---> exit()           =
* [gadgt]---> pop/ret          = exit()
  [arg2 ]---> 0                =
  [ra3  ]---> func3()          +
* [gadgt]---> pop/pop/ret      + func3()
  [arg3 ] ...                  +
~~~~

# Defenses: Control-flow Integrity
- Control-flow at the compilation time should be enforced at runtime!
- Vendors adoptions:
    - [Control-flow Guard (CFG) by Microsoft from Windows 10/8.1](https://docs.microsoft.com/en-us/windows/desktop/secbp/control-flow-guard)
    - [LLVM forward CFI by Android (Pixel 3)](https://security.googleblog.com/2018/10/posted-by-sami-tolvanen-staff-software.html)
    - [LLVM forward CFI by Google Chrome (dev)](https://www.chromium.org/developers/testing/control-flow-integrity)
- Hardware solutions:
    - Intel: [Control-flow Enforcement (CET)](https://software.intel.com/sites/default/files/managed/4d/2a/control-flow-enforcement-technology-preview.pdf)
    - ARM v8,3: [PAC in iOS 12 by Apple](https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf)

# Basic Idea: Enforcing Control-flow Graphs
- Forward CFI: protecting indirect calls (e.g., jmp eax)
    - Course-grained: static call graphs
    - Finer-grained: type-based, Input-based, etc.
- Backward CFI: protecting returns (e.g., ret)
    - Safe/shadow stack

-> CPU overheads: 5-20% in forward CFIs, 1-5% in backwards CFIs

;
; XXX. add -lto -fcfi? example?
;

# Trends of Vulnerability Classes

 @img(w110%, img/trend.png)

Ref. [Exploitation Trends: From Potential Risk to Actual Risk, RSA 2015](https://www.rsaconference.com/writable/presentations/file_upload/br-t07-exploitation-trends-from-potential-risk-to-actual-risk.pdf)

# Three Emerging Classes of Vulnerabilities
1. Type confusion: e.g., bad casting in C++
1. Race condition: e.g., double fetching
1. Uninitialized read: e.g., struct padding issues

# Type Casting in C++

 @img(w50%, img/casting0.svg)

~~~~{.cc .numberLines}
class SVGElement: public Element { ... };

SVGElement *pCanvas = new SVGElement();
~~~~

# Upcasting and Downcasting in C++

 @img(w50%, img/casting1.svg)

~~~~{.cc .numberLines}
// (1) valid upcast from pCanvas to pElem
Element *pElem = static_cast<Element*>(pCanvas);

// (2) valid downcast from pElem to pCanvasAgain (== pCanvas)
SVGElement *pCanvasAgain = static_cast<SVGElement*>(pElem);
~~~~

# Dynamic Casting in C++ (Downcasting)

 @img(w50%, img/casting2.svg)

~~~~{.cc .numberLines}
Element *pDom = new Element();

// (3) invalid downcast with dynamic_cast, but no corruption
SVGElement *p = dynamic_cast<SVGElement*>(pDom);
if (p) {
    p->m_className = "my-canvas";
}
~~~~

# Static Casting in C++ (Downcasting)

 @img(w50%, img/casting2.svg)

~~~~{.cc .numberLines}
// (4) BUG: invalid downcast
SVGElement *p = static_cast<SVGElement*>(pDom);

// (5) leads to memory corruption!
p->m_className = "my-canvas";
~~~~

# Type Confusion: Bad Casting in C++
- Two (important) type castings:
    1. static_cast<>: verify the correctness at compilation
    2. dynamic_cast<>: verify the correctness at runtime
- Incorrect downcasting (via static_cast<>) results in memory violation
- dynamic_cast<> requires RTTI, incurring non-trivial perf. overheads

# CVE-2013-0912 and Pwn2Own 2013

 @img(w80%, img/svg-class-hierarchy.svg)

# Exercise: Real-world Examples
- Ex1. Linux Perf (CVE-2009-3234/+)
    - -> Race condition: double fetching in Linux
- Ex2. Linux USB (CVE-2016-4482)
    - -> Uninitialized read via struct padding

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
1. Partialy reading after the size attribute
1. Ensuring the atomicity of previous checked size

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

# Exercise: Real-world Examples
- Ex1. Linux Perf (CVE-2009-3234/+)
    - -> Race condition: double fetching in Linux
- Ex2. Linux USB (CVE-2016-4482)
    - -> Uninitialized read via struct padding

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

- Zero-ing out via memset(): initializing two times!

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

# Summary
- Modern attacks are using **ROP** to defeat DEP/NX
- Learn three emerging, critical classes of vulnerabilities
    - **Type confusion**: e.g., bad casting in C++
    - **Race condition**: e.g., double fetching
    - **Uninitialized read**: e.g., struct padding issues


# References

- [CVE-2016-4482](https://bugzilla.redhat.com/show_bug.cgi?id=1332932)
- [CVE-2013-0912](https://nvd.nist.gov/vuln/detail/CVE-2013-0912)
- [CVE-2009-3234](https://www.oreilly.com/library/view/a-guide-to/9781597494861/OEBPS/B9781597494861000048a.htm)
- [Proactive Kernel Memory Initialization to Eliminate Data Leakages](https://taesoo.kim/pubs/2016/lu:unisan.pdf)
- [Precise and Scalable Detection of Double-Fetch Bugs in OS Kernels](https://taesoo.kim/pubs/2018/xu:deadline.pdf)
- [Return-oriented Programming](https://www.blackhat.com/presentations/bh-usa-08/Shacham/BH_US_08_Shacham_Return_Oriented_Programming.pdf)
- Unisan: [paper](https://taesoo.kim/pubs/2016/lu:unisan.pdf)/[slides](https://taesoo.kim/pubs/2016/lu:unisan-slides.pdf)
