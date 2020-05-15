#include <sys/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>
#include <xenctrl.h>
#include <xen/sys/privcmd.h>
#include <errno.h>
#include <xen/xen.h>
#include <stdio.h>



int main(int argc, char** argv){
        int fd;
        int ret;
        ret=0;
        int fault_site[100];
        privcmd_hypercall_t my_hypercall={
                __HYPERVISOR_get_site,
                {(long long int)&fault_site,0,0,0,0}
        };

        fd = open("/proc/xen/privcmd",O_RDWR);
        if (fd<0){
                perror("cannot open privcmd");
                return 0;
        }
        ret=ioctl(fd,IOCTL_PRIVCMD_HYPERCALL, &my_hypercall);
	printf("%d",fault_site[0]);
	FILE *fp;
	fp=fopen("/dev/fault","w");
	fwrite(fault_site, sizeof(fault_site), 1, fp);
	fclose(fp);
	
        return 0;

}



