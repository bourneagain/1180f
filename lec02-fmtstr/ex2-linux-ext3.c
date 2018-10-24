/* CVE-2013-1848 */
/*  ref. https://github.com/torvalds/linux, @8d0c2d10dd72c5292eda7a06231056a4c972e4cc */

/* fs/ext3/super.c */
void ext3_msg(struct super_block *sb, const char *prefix,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk("%sEXT3-fs (%s): %pV\n", prefix, sb->s_id, &vaf);

	va_end(args);
}

/*
 * Get the superblock
 */
static ext3_fsblk_t get_sb_block(void **data, struct super_block *sb)
{
	char *options = (char *) *data;

	if (!options || strncmp(options, "sb=", 3) != 0)
		return 1;	/* Default location */
	options += 3;
  
	if (*options && *options != ',') {
		ext3_msg(sb, "error: invalid sb specification: %s", (char *) *data);
		return 1;
	}
  ...
}

/*
 * Open the external journal device
 */
static struct block_device *ext3_blkdev_get(dev_t dev, struct super_block *sb)
{
	struct block_device *bdev;
	char b[BDEVNAME_SIZE];

	bdev = blkdev_get_by_dev(dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL, sb);
	if (IS_ERR(bdev))
		goto fail;
	return bdev;

fail:
	ext3_msg(sb, "error: failed to open journal device %s: %ld",
		__bdevname(dev, b), PTR_ERR(bdev));

	return NULL;
}
