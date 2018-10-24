CFLAGS := -O0 -g
SHELL := bash
ALL := cmp64 cmp32 builtin fwrap-yes fwrap-no

all: $(ALL)

%64: %.c
	$(CC) $(CFLAGS) -o $@ $^
%32: %.c
	$(CC) $(CFLAGS) -m32 -o $@ $^

fwrap-yes: fwrap.c
	$(CC) -g -O3 -fwrapv -o $@ $^
fwrap-no: fwrap.c
	$(CC) -g -O3 -fno-wrapv -o $@ $^

check-fwrapv: $(ALL)
	-diff -urN <(./check-func.py fwrap-no main) \
              <(./check-func.py fwrap-yes main)
	echo 2147483647 | ./fwrap-no
	echo 2147483647 | ./fwrap-yes

clean:
	rm -f $(ALL)

.PHONY: all clean