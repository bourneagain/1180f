ALL := fortify-yes fortify-no

CFLAGS_YES := -g -D_FORTIFY_SOURCE=2 -O2 -fstack-protector
CFLAGS_NO  := -g -D_FORTIFY_SOURCE=0 -O2 -fstack-protector

SHELL := bash

all: $(ALL)

%-yes: %.c
	$(CC) $(CFLAGS_YES) -o $@ $^

%-no: %.c
	$(CC) $(CFLAGS_NO) -o $@ $^

diff: $(ALL)
	diff -urN <(objdump -M intel-mnemonic -d fortify-no) <(objdump -M intel-mnemonic -d fortify-yes)

clean:
	rm -f $(ALL)

.PHONY: all claen diff