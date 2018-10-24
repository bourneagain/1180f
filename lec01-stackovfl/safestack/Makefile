CC := clang
SHELL := bash
CFLAGS := -O0 -g
ALL := safestack-yes safestack-no shadowstack-yes shadowstack-no

all: $(ALL)

safestack-yes: safestack.c
	$(CC) $(CFLAGS) -fsanitize=safe-stack -o $@ $^

safestack-no: safestack.c
	$(CC) $(CFLAGS) -o $@ $^

shadowstack-yes: shadowstack.c
	$(CC) $(CFLAGS) -fsanitize=shadow-call-stack -o $@ $^

shadowstack-no: shadowstack.c
	$(CC) $(CFLAGS) -o $@ $^

check-safestack: $(ALL)
	diff -urN <(./check-func.py safestack-no vuln) \
	          <(./check-func.py safestack-yes vuln)

check-shadowstack: $(ALL)
	diff -urN <(./check-func.py shadowstack-no vuln) \
	          <(./check-func.py shadowstack-yes vuln)


clean:
	rm -f $(ALL)

.PHONY: all clean