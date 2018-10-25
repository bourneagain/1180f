all:

release:
	(cd ..; rsync -a --exclude='.git/' repo/ release/)
	rm -f ../release/NOTE.plan
	(cd ../release; git add .; git commit -a -m "release")
	(cd ../release; git push origin master)

build:
	docker build . -t nutanix
	docker save nutanix | xz -9 > ../nutanix.tar.xz

run:
	docker run --privileged -it --rm nutanix /bin/bash

.PHONY: all release build run