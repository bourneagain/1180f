/* CVE-2013-2851 */
/*  ref. https://github.com/torvalds/linux, @ffc8b30866879ed9ba62bd0a86fecdbd51cd3d19 */

/* block/genhd.c */
static void register_disk(struct gendisk *disk) {
  struct device *ddev = disk_to_dev(disk);
  
  ddev->parent = disk->driverfs_dev;
  dev_set_name(ddev, disk->disk_name);

  /* delay uevents, until we scanned partition table */
  dev_set_uevent_suppress(ddev, 1);

  if (device_add(ddev))
    return;
  ...
}

/* drivers/block/ndb.c */
static int __nbd_ioctl(struct block_device *bdev, struct nbd_device *nbd,
                       unsigned int cmd, unsigned long arg) {
   switch (cmd) {
   ...
   case NBD_DO_IT: {
     struct task_struct *thread;
     ...
     thread = kthread_create(nbd_thread, nbd, nbd->disk->disk_name);
     if (IS_ERR(thread)) {
       return PTR_ERR(thread);
     }
   }
   ...
  }
}

/**
 * dev_set_name - set a device name
 * @dev: device
 * @fmt: format string for the device's name
 */
int dev_set_name(struct device *dev, const char *fmt, ...) {
	va_list vargs;
	int err;

	va_start(vargs, fmt);
	err = kobject_set_name_vargs(&dev->kobj, fmt, vargs);
	va_end(vargs);
	return err;
}

/**
 * kthread_create - create a kthread on the current node
 * @threadfn: the function to run in the thread
 * @namefmt: printf-style format string for the thread name
 * @arg...: arguments for @namefmt.
 */
#define kthread_create(threadfn, data, namefmt, arg...) ...
