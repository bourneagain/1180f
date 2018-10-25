/* CVE-2016-4482
   ref. Linux, @681fef8380eb818c0b845fca5d2ab1dcbab114ee */

// @include/uapi/linux/usbdevice_fs.h
struct usbdevfs_connectinfo {
  unsigned int devnum;
  unsigned char slow;
};

static long usbdev_do_ioctl(struct file *file, unsigned int cmd, void __user *p) {
  struct usb_dev_state *ps = file->private_data;
  struct usb_device *dev = ps->dev;
  int ret = -ENOTTY;

  if (!(file->f_mode & FMODE_WRITE))
    return -EPERM;

  usb_lock_device(dev);
  ...
  switch (cmd) {
  ...
  case USBDEVFS_CONNECTINFO:
    snoop(&dev->dev, "%s: CONNECTINFO\n", __func__);
    ret = proc_connectinfo(ps, p);
    break;
  ...
  }
  return ret;
}

static int proc_connectinfo(struct usb_dev_state *ps, void __user *arg) {
  struct usbdevfs_connectinfo ci = {
    .devnum = ps->dev->devnum,
    .slow = ps->dev->speed == USB_SPEED_LOW
  };

  if (copy_to_user(arg, &ci, sizeof(ci)))
    return -EFAULT;
  return 0;
}