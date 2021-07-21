#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>

extern int* pid_capable;
extern int pid_index;

static void append_capable_pid(unsigned long arg) {
    void __user *argp = (void __user *)(unsigned long)(arg);
    int ppid;
    if(copy_from_user(&ppid, argp, sizeof(int)))
        return;
    if (pid_index >= 99)
        return;
    printk(KERN_EMERG "add pid %d to monitoring list\n", ppid);
    if (pid_capable == 0) {
        pid_capable = (int *)kmalloc(101*sizeof(int), GFP_KERNEL);
        memset(pid_capable, 0, 101*sizeof(int));
    }
    pid_capable[pid_index++] = ppid;
}

static int under_monitor(int pid) {
    if (pid_capable == 0) {
        pid_capable = (int *)kmalloc(101*sizeof(int), GFP_KERNEL);
        memset(pid_capable, 0, 101*sizeof(int));
    }
    int i;
    for (i=0; i<100; i++) {
        if (pid_capable[i] == pid)
            return 1;
    }
    return 0;
}
