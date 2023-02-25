#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/string.h>

#define ADD 0x6666
#define DELETE 0x7777
#define EDIT 0x8888
#define SHOW 0x9999

typedef struct linkedlist
{
	uint64_t size;
	struct linkedlist *next;
	char* data;
}LinkedList;

LinkedList *head = NULL;

static long babyLinkedList_ioctl(struct file*, unsigned int, unsigned long);

struct proc_dir_entry *babyLinkedList_file_entry;
static const struct file_operations babyLinkedList_file_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = babyLinkedList_ioctl
};

char *DATA = "NCTF2022";

static long babyLinkedList_ioctl(struct file *fd, unsigned int cmd, unsigned long arg)
{
	LinkedList *tmp, *prev;
	int ret;

	struct data
	{
		uint64_t size;
		char *data;
	};
	struct data *n;
	n = (struct data*) arg;

	switch(cmd)
	{
		case ADD:
			if(n->size > 0x40 || n->size<0x20)
				return -1;
			else
			{
				tmp = kmalloc(0x40, GFP_KERNEL);
				tmp->size = n->size;
				tmp->next = head;
				head = tmp;
				tmp->data = kmalloc(n->size, GFP_KERNEL);
				ret = copy_from_user((void*)(tmp->data), (void*)DATA, 0x8);
				ret = copy_from_user((void*)(tmp->data+0x10), (void*)(n->data), 0x8);
			}
			break;
		case DELETE:
			if(head != NULL)
			{
				prev = head->next;
				tmp = head;
				if(tmp != NULL )
				{
					printk(KERN_ALERT "[NCTF2022:] OK, you can delete it");
					if(prev != NULL)
					{
						head = prev;
						kfree(tmp);
						kfree(tmp->data);
					}
					else
					{
						kfree(tmp->data);
						ret = copy_to_user((void*)(n->data), (void*)(tmp->data+0x8), 0x10);
						head = prev;
					}
				}
			}
			break;
		case EDIT:
			ret = copy_from_user((void*)DATA, (void*)n->data, 0x4);
			break;
		case SHOW:
			ret = copy_to_user((void*)n->data, (void*)DATA, 0x8);
			break;
		default:
			break;
			
	}
	return 0;
}


static int babyLinkedList_init(void) 
{
	babyLinkedList_file_entry = proc_create("babyLinkedList", 0, NULL, &babyLinkedList_file_fops);
	if(babyLinkedList_file_entry == NULL)
		return -ENOMEM;
	printk(KERN_INFO "Welcome to NCTF 2022!\n");
	return 0;
}

static void babyLinkedList_exit(void) 
{
	remove_proc_entry("babyLinkedList", NULL);
	printk(KERN_INFO "Bye, hacker!\n");
}
module_init(babyLinkedList_init);
module_exit(babyLinkedList_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("X1cT34m-FXC");
MODULE_DESCRIPTION("NCTF 2022 - babyyLinkedList");
