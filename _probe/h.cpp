#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#if __has_include(<dirent.h>)
#include <dirent.h>
#error "dirent.h EXISTS"
#endif
#if __has_include(<unistd.h>)
#include <unistd.h>
#error "unistd.h EXISTS"
#endif
#if __has_include(<sys/utime.h>)
#error "sys/utime.h EXISTS"
#endif
#if __has_include(<utime.h>)
#error "utime.h EXISTS"
#endif
#if __has_include(<sys/ioctl.h>)
#error "sys/ioctl.h EXISTS"
#endif
int main(){return 0;}
