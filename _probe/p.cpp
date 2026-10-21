#include <sys/types.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstddef>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <sys/utime.h>
#include <fcntl.h>
#endif
int main() {
#ifdef S_ISLNK
    puts("HAS S_ISLNK");
#else
    puts("NO S_ISLNK");
#endif
#ifdef _S_IFLNK
    puts("HAS _S_IFLNK");
#endif
#ifdef lstat
    puts("HAS lstat macro");
#endif
    printf("sizeof(stat)=%d off(st_mode)=%d\n", (int)sizeof(struct stat), (int)offsetof(struct stat, st_mode));
    printf("S_IFDIR=0x%x S_IFREG=0x%x\n", (unsigned)S_IFDIR, (unsigned)S_IFREG);
    return 0;
}
