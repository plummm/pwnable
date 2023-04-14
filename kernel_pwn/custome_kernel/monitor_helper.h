#pragma once
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>

#define CLEAR_LIST 0
#define PRINT_STACK_DEBUG 1
#define PRINT_PAGE_ALLOC 1 << 1
#define PRINT_PAGE_FREE 1 << 2
#define PRINT_MSG 1 << 3
#define PRINT_USER_KEY_PAYLOAD 1 << 4
#define PRINT_OOB_INFO 1 << 5
#define PRINT_ANY_PROC 1 << 6
#define PRINT_PAGE_CUR_ORDER 1 << 7
#define PRINT_PAGE_FREE_DETAIL 1 << 8
#define PRINT_XATTR 1 << 9
#define PRINT_OOB_DETAIL 1 << 10
#define PRINT_TARGET_SLAB 1 << 11

struct monitor_pid_struct {
    struct list_head list;
    int pid;
    unsigned int flag;
};

struct kernel_hack {
    void *addr;
    int size;
    void __user *user_addr;
};

extern struct list_head pid_list;

static void read_kernel_memory(u_int64_t arg) {
    struct kernel_hack data;
    char *tmp;

    void __user *argp = (void __user *)(u_int64_t)(arg);
    copy_from_user(&data, argp, sizeof(struct kernel_hack));

    tmp = kmalloc(data.size, GFP_KERNEL);
    memcpy(tmp, data.addr, data.size);
    if (copy_to_user(data.user_addr, data.addr, data.size)) {
        printk(KERN_EMERG "[read_kernel_memory] fail to copy 0x%llx", data.addr);
    }
}

static void append_capable_pid(unsigned long arg) {
    struct monitor_pid_struct *mon_pid, *it;
    unsigned int flag;
    int pid = current->pid;
    void __user *argp = (void __user *)(unsigned long)(arg);

    copy_from_user(&flag, argp, sizeof(unsigned int));
    //printk(KERN_DEBUG "add pid %d to monitoring list", pid);

    mon_pid = (struct monitor_pid_struct *)kmalloc(sizeof(struct monitor_pid_struct), GFP_KERNEL);
    mon_pid->pid = pid;
    mon_pid->flag = flag;
    if (flag & PRINT_ANY_PROC) {
        mon_pid->pid = -1;
    }
    if (flag == CLEAR_LIST) {
        list_for_each_entry(mon_pid, &pid_list, list) {
            list_del(&mon_pid->list);
        }
        return;
    }

    list_for_each_entry(it, &pid_list, list) {
        if (it->pid == pid) {
            it->flag = flag;
            return;
        }
    }
    list_add(&mon_pid->list, &pid_list);
}

static unsigned int under_monitor(int pid) {
    struct monitor_pid_struct *mon_pid;
    list_for_each_entry(mon_pid, &pid_list, list) {
		if (mon_pid->pid == pid || mon_pid->pid == -1) {
			return mon_pid->flag;
		}
	}
    return 0;
}

static bool monitor_is_empty(void) {
    return list_empty(&pid_list);
}

static bool monitor_debug(unsigned int flag) {
    return flag & PRINT_STACK_DEBUG;
}

static bool monitor_page_alloc(unsigned int flag) {
    return flag & PRINT_PAGE_ALLOC;
}

static bool monitor_page_free(unsigned int flag) {
    return flag & PRINT_PAGE_FREE;
}

static bool monitor_page_free_detail(unsigned int flag) {
    return flag & PRINT_PAGE_FREE_DETAIL;
}

static bool monitor_msg(unsigned int flag) {
    return flag & PRINT_MSG;
}

static bool monitor_user_key_payload(unsigned int flag) {
    return flag & PRINT_USER_KEY_PAYLOAD;
}

static bool monitor_oob_info(unsigned int flag) {
    return flag & PRINT_OOB_INFO;
}

static bool monitor_page_cur_order(unsigned int flag) {
    return flag & PRINT_PAGE_CUR_ORDER;
}

static bool monitor_xattr(unsigned int flag) {
    return flag & PRINT_XATTR;
}

static bool monitor_oob_detail(unsigned int flag) {
    return flag & PRINT_OOB_DETAIL;
}

static bool monitor_target_slab(unsigned int flag) {
    return flag & PRINT_TARGET_SLAB;
}

