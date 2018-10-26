
# Exercise: Real-world Examples
- Ex1. Linux Perf (CVE-2009-3234/+)
- Ex2. Linux USB (CVE-2016-4482)

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
