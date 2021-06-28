#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/delay.h>

#define PWN_LOGIN _IO('p', 1)
#define PWN_ADMIN _IO('p', 2)
#define PWN_SUDO _IO('p', 3)
#define PWN_LOGOUT _IO('p', 4)

MODULE_LICENSE("GPL");

char flag[128];

static int device_open(struct inode *inode, struct file *flip) {
	printk(KERN_ALERT "Device opened.\n");
	return 0;
}

static int device_release(struct inode *inode, struct file *flip) {
	printk(KERN_ALERT "Device closed.\n");
	return 0;
}

unsigned int privilege_level = 0;

static long device_ioctl(struct file *flip, unsigned int ioctl_num, unsigned long ioctl_param) {
	if (ioctl_num == PWN_LOGIN && strcmp((const char *)ioctl_param, "SECRET") == 0) {
		privilege_level = 1;
		printk(KERN_ALERT "PWN_LOGIN set privilege level to %d.\n", privilege_level);
	} else if (ioctl_num == PWN_ADMIN && strcmp((const char *)ioctl_param, flag) == 0) {
		privilege_level = 2;
		printk(KERN_ALERT "PWN_ADMIN set privilege level to %d.\n", privilege_level);
	} else if (ioctl_num == PWN_SUDO && privilege_level > 1) {
		printk(KERN_ALERT "PWN_SUDO granting root privilege level is %d.\n", privilege_level);
		commit_creds(prepare_kernel_cred(0));
	} else if (ioctl_num == PWN_LOGOUT) {
		if (privilege_level) {
			printk(KERN_ALERT "PWN_LOGOUT decrementing privilege level.\n");
			usleep_range(0, 1);
			privilege_level--;
		}
	}
	return 0;
}

static struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release
};

struct proc_dir_entry *proc_entry = NULL;

int init_module() {
	loff_t offset = 0;
	struct file *flag_fd;
	flag_fd = filp_open("/flag", O_RDONLY, 0);
	kernel_read(flag_fd, flag, 128, &offset);
	filp_close(flag_fd, NULL);
	proc_entry = proc_create("pwn-college-race", 0666, NULL, &fops);
	return 0;
}

void cleanup_module() {
	if (proc_entry) proc_remove(proc_entry);
}
