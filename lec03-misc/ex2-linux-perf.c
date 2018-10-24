/* CVE-2009-3234 and double fetching found in 2017
   ref. Linux, @b3e62e35058fc744ac794611f4e79bcd1c5a4b83, @f12f42acdbb577a12eecfcebbbec41c81505c4dc */

SYSCALL_DEFINE5(perf_event_open, struct perf_event_attr __user *, attr_uptr, ...) {
  err = perf_copy_attr(attr_uptr, &attr); ...
}

static int perf_copy_attr(struct perf_counter_attr __user *uattr,
                          struct perf_counter_attr *attr) {
  int ret;
  u32 size;

  if (!access_ok(VERIFY_WRITE, uattr, PERF_ATTR_SIZE_VER0))
    return -EFAULT;

  /* zero the full structure, so that a short copy will be nice. */
  memset(attr, 0, sizeof(*attr));
  ret = get_user(size, &uattr->size);
  if (ret)
    return ret;

  if (size > PAGE_SIZE)	/* silly large */
    goto err_size;
  if (!size)            /* abi compat */
    size = PERF_ATTR_SIZE_VER0;
  if (size < PERF_ATTR_SIZE_VER0)
    goto err_size;

  /* If we're handed a bigger struct than we know of,
   * ensure all the unknown bits are 0.	 */
  if (size > sizeof(*attr)) {
    unsigned long val;
    unsigned long __user *addr, __user *end;

    addr = PTR_ALIGN((void __user *)uattr + sizeof(*attr),
                     sizeof(unsigned long));
    end  = PTR_ALIGN((void __user *)uattr + size,
                     sizeof(unsigned long));

    for (; addr < end; addr += sizeof(unsigned long)) {
      ret = get_user(val, addr);
      if (ret)
        return ret;
      if (val)
        goto err_size;
    }
  }

  ret = copy_from_user(attr, uattr, size);
  if (ret)
    return -EFAULT;
  ...
out:
  return ret;
err_size:
  put_user(sizeof(*attr), &uattr->size);
  ret = -E2BIG;
  goto out;
}