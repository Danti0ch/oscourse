void (*volatile sys_yield)(void);
int (*volatile cprintf)(const char *fmt, ...);

void
umain(int argc, char **argv) {
    int i, j;

    for (j = 0; j < 3; ++j) {
        for (i = 0; i < 100; ++i){
            cprintf("%d\n", i);
        }
        sys_yield();
    }
}
