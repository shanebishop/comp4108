
       #include <dirent.h>     /* Defines DT_* constants */
       #include <fcntl.h>
       #include <stdio.h>
       #include <unistd.h>
       #include <stdlib.h>
       #include <sys/stat.h>
       #include <sys/syscall.h>
       #include <string.h>

       #define handle_error(msg) \
               do { perror(msg); exit(EXIT_FAILURE); } while (0)

       struct linux_dirent {
           unsigned long  d_ino;
           off_t          d_off;
           unsigned short d_reclen;
           char           d_name[];
       };

       #define BUF_SIZE 1024

int starts_with(const char *prefix, const char *str)
{
  return strncmp(prefix, str, strlen(prefix)) == 0;
}

       int
       main(int argc, char *argv[])
       {
           unsigned int count = BUF_SIZE;
           int fd, nread;
           char buf[count];
           struct linux_dirent *d;
           unsigned int bpos;
           char d_type;

           // This I added
           char k_buf[count];
           unsigned int i = 0, j = 0;
           char starts_with_prefix = 0;
           char *magic_prefix = "foo";
           char *user_buf = NULL;

           fd = open(argc > 1 ? argv[1] : ".", O_RDONLY | O_DIRECTORY);
           if (fd == -1)
               handle_error("open");

           for ( ; ; ) {
               nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
               if (nread == -1)
                   handle_error("getdents");

               if (nread == 0)
                   break;

               user_buf = (char*) buf;

               // Fill k_buf with 0x00 bytes
               for (i = 0; i < count; ++i) {
                 k_buf[i] = 0x00;
               }

               for (bpos = 0; bpos < (unsigned int)nread;) {
                 d = (struct linux_dirent *) (user_buf + bpos);
                 starts_with_prefix = starts_with(magic_prefix, d->d_name);

                 printf("entry: %s%s\n", d->d_name,
           starts_with_prefix ? " (hidden)" : "");

                 if (!starts_with_prefix) {
                   for (i = bpos; i < bpos + d->d_reclen; ++i) {
                     k_buf[j++] = user_buf[i];
                   }
                 }

                 bpos += d->d_reclen;
               }

               // Copy k_buf to user_buf - user_buf == dirp
               for (i = 0; i < count; ++i) {
                 user_buf[i] = k_buf[i];
               }
           }

           exit(EXIT_SUCCESS);
       }
