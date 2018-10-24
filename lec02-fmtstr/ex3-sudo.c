/* CVE-2012-0809 */
/*  ref: https://github.com/millert/sudo, @697caf8df32270a2676cd54e69d1f72d8d172d1f */

/* src/sudo.c */
int main(int argc, char *argv[], char *envp[]) {
  ...
  /* Parse command line arguments. */
  sudo_mode = parse_args(argc, argv, &nargc, &nargv, &settings, &env_add);
  sudo_debug(9, "sudo_mode %d", sudo_mode);
  ...
}

/*
 * Simple debugging/logging.
 */
void sudo_debug(int level, const char *fmt, ...) {
  va_list ap;
  char *fmt2;

  if (level > debug_level)
    return;

  /* Backet fmt with program name and a newline to make it a single write */
  easprintf(&fmt2, "%s: %s\n", getprogname(), fmt);
  va_start(ap, fmt);
  vfprintf(stderr, fmt2, ap);
  va_end(ap);
  efree(fmt2);
}

/* NOTE. */
/*  easprintf: an error-free version of asprintf() */
/*  efree: an error-free version of free() */