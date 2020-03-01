#include <linux/usb/composite.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>

static wait_queue_head_t rsw_waitq;
static struct semaphore rsw_sema;

static struct usb_descriptor_header *empty_descriptors[] = {NULL};

static int rsw_set_alt(struct usb_function *f, unsigned int interface, unsigned int alt) { return 0; }
static void rsw_disable(struct usb_function *f) {}

static bool rsw_req_match(
		struct usb_function *f,
		const struct usb_ctrlrequest *ctrl,
		bool config0)
{
	switch (ctrl->bRequestType << 8 | ctrl->bRequest) {
	case 0xC053:
	case 0x4051:
	case 0x4050:
		return true;
	default:
		return false;
	}
}

static int rsw_setup(
		struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request *req = cdev->req;
	u16 w_length = le16_to_cpu(ctrl->wLength);

	switch (ctrl->bRequestType << 8 | ctrl->bRequest) {
	case 0xC053:
		if (w_length == 4) {
			/* advertise Carplay support */
			*(u32 *)req->buf = 1;
			req->zero = 0;
			req->length = 4;
			return usb_ep_queue(cdev->gadget->ep0, req, GFP_ATOMIC);
		} else {
			return -ENOTSUPP;
		}
	case 0x4051:
	case 0x4050:
		/* notify waitq and wait here */
		pr_info("apple_rsw: got role switch request\n");
		up(&rsw_sema);
		wake_up_interruptible(&rsw_waitq);
		return 0;
	default:
		return -ENOTSUPP;
	}
}

static void rsw_free(struct usb_function *f)
{
	kfree(f);
}

static struct usb_function *rsw_alloc(struct usb_function_instance *fi)
{
	struct usb_function *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return ERR_PTR(-ENOMEM);

	f->name = "apple_rsw";
	f->fs_descriptors = empty_descriptors;
	f->hs_descriptors = empty_descriptors;
	f->free_func = rsw_free;
	f->set_alt = rsw_set_alt;
	f->disable = rsw_disable;
	f->req_match = rsw_req_match;
	f->setup = rsw_setup;
	return f;
}

static void rsw_attr_release(struct config_item *item)
{
	struct usb_function_instance *fi = container_of(
			to_config_group(item),
			struct usb_function_instance,
			group);

	usb_put_function_instance(fi);
}

static void rsw_free_inst(struct usb_function_instance *fi)
{
	kfree(fi);
}

static struct usb_function_instance *rsw_alloc_inst(void)
{
	struct usb_function_instance *fi;

	static struct configfs_item_operations rsw_ops = {
		.release = rsw_attr_release,
	};
	static struct configfs_attribute *rsw_attrs[] = {NULL};
	static struct config_item_type rsw_type = {
		.ct_item_ops = &rsw_ops,
		.ct_attrs = rsw_attrs,
		.ct_owner = THIS_MODULE,
	};

	fi = kzalloc(sizeof(*fi), GFP_KERNEL);
	if (!fi)
		return ERR_PTR(-ENOMEM);

	fi->free_func_inst = rsw_free_inst;
	config_group_init_type_name(&fi->group, "", &rsw_type);
	return fi;
}

DECLARE_USB_FUNCTION(apple_rsw, rsw_alloc_inst, rsw_alloc);

static __poll_t rsw_fop_poll(struct file *file, struct poll_table_struct *pts)
{
	poll_wait(file, &rsw_waitq, pts);
	return rsw_sema.count > 0 ? EPOLLIN | EPOLLRDNORM : 0;
}

static ssize_t rsw_fop_read(struct file *file, char __user *buf, size_t sz, loff_t *pos)
{
	int ret;

	if (sz == 0)
		return 0;

	ret = wait_event_interruptible(rsw_waitq, down_trylock(&rsw_sema) == 0);
	if (ret)
		return ret;

	if (copy_to_user(buf, "x", 1))
		return -EFAULT;
	else
		return 1;
}

static struct file_operations rsw_misc_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.poll = rsw_fop_poll,
	.read = rsw_fop_read,
};

static struct miscdevice rsw_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "apple_rsw",
	.fops = &rsw_misc_fops,
};

static int rsw_module_init(void)
{
	int ret;

	init_waitqueue_head(&rsw_waitq);
	sema_init(&rsw_sema, 0);

	ret = misc_register(&rsw_misc);
	if (ret < 0)
		return ret;

	ret = usb_function_register(&apple_rswusb_func);
	if (ret < 0) {
		misc_deregister(&rsw_misc);
		return ret;
	}

	return 0;
}

static void rsw_module_exit(void)
{
	usb_function_unregister(&apple_rswusb_func);
	misc_deregister(&rsw_misc);
}

module_init(rsw_module_init);
module_exit(rsw_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gavin Li");
