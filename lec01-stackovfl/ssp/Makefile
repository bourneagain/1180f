CFLAGS := -g -O0
SHELL := bash

ALL := ovfl ssp-all ssp-strong ssp-explicit ssp-default loc stackcheck-no stackcheck-yes canary

all: $(ALL)

%-default: %.c
	$(CC) -o $@ -fstack-protector $(CLFAGS) $^
%-all: %.c
	$(CC) -o $@ -fstack-protector-all $(CLFAGS) $^
%-strong: %.c
	$(CC) -o $@ -fstack-protector-strong $(CLFAGS) $^
%-explicit: %.c
	$(CC) -o $@ -fstack-protector-explicit $(CLFAGS) $^
ovfl: ovfl.c
	$(CC) -o $@ -fstack-protector $(CLFAGS) $^
canary: canary.c
	$(CC) -o $@ -fstack-protector-all $(CLFAGS) $^

stackcheck-no: stackcheck.c
	$(CC) -o $@ $(CFLAGS) -fno-stack-check $^
stackcheck-yes: stackcheck.c
	$(CC) -o $@ $(CFLAGS) -fstack-check $^

stackcheck-yes: stackcheck.c

check-ssp: $(ALL)
	diff -urN <(./check-func.py ssp-explicit func1_benign) \
              <(./check-func.py ssp-all func1_benign)
check-sspopts: $(ALL)
	./check-ssp.py ssp-*
check-loc: $(ALL)
	./check-loc.py ./loc
check-stackcheck: $(ALL)
	./check-func.py stackcheck-no main
	./check-func.py stackcheck-yes main

clean:
	rm -f $(ALL)

.PHONY: all