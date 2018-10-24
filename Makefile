all:

release:
	(cd ..; rsync -a --exclude='.git/' repo/ release/)
	rm -f ../release/NOTE.plan
	(cd ../release; git add .; git commit -a -m "release"; git push)

.PHONY: all release