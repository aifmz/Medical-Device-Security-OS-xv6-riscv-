#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/fs.h"
#include "kernel/file.h"
#include "user/user.h"
#include "kernel/fcntl.h"

char *argv[] = { "sh", 0 };

int
main(void)
{
  char username[32], password[32], hashed[32], buf[1024];
  int fd, n, uid, gid;

  while(1){
    printf("login: ");
    gets(username, sizeof(username));
    {
      int ulen = strlen(username);
      if(ulen > 0 && username[ulen - 1] == '\n')
        username[ulen - 1] = 0;
    }

    printf("password: ");
    gets(password, sizeof(password));
    {
      int plen = strlen(password);
      if(plen > 0 && password[plen - 1] == '\n')
        password[plen - 1] = 0;
    }

    // Hash password
    for(int i = 0; password[i]; i++){
      hashed[i] = password[i] ^ 0xAA;
    }
    hashed[strlen(password)] = 0;

    // Open /etc/passwd
    if((fd = open("/etc/passwd", O_RDONLY)) < 0){
      printf("login: cannot open /etc/passwd\n");
      continue;
    }

    n = read(fd, buf, sizeof(buf));
    close(fd);
    if(n < 0){
      printf("login: read error\n");
      continue;
    }
    buf[n] = 0;

    // Parse lines
    char *line = buf;
    int found = 0;
    while(*line){
      char *colon1 = strchr(line, ':');
      if(!colon1) break;
      *colon1 = 0;
      char *user = line;
      line = colon1 + 1;

      char *colon2 = strchr(line, ':');
      if(!colon2) break;
      *colon2 = 0;
      char *pass = line;
      line = colon2 + 1;

      char *colon3 = strchr(line, ':');
      if(!colon3) break;
      *colon3 = 0;
      uid = atoi(line);
      line = colon3 + 1;

      char *colon4 = strchr(line, '\n');
      if(!colon4) break;
      *colon4 = 0;
      gid = atoi(line);
      line = colon4 + 1;

      if(strcmp(user, username) == 0 && strcmp(pass, hashed) == 0){
        found = 1;
        break;
      }
    }

    if(found){
      audit_login(1, username);
      setuid(uid);
      setgid(gid);
      exec("sh", argv);
      printf("login: exec sh failed\n");
      exit(1);
    } else {
      audit_login(0, username);
      printf("login: invalid username or password\n");
    }
  }
  return 0;
}