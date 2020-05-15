#include <sys/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>
#include <xenctrl.h>
#include <xen/sys/privcmd.h>
#include <errno.h>
#include <xen/xen.h>



int main(void){
	int fd; //, covFd;
	int ret;
	privcmd_hypercall_t unset_cover={
			__HYPERVISOR_unset_cov_array,
			{0,0,0,0,0}
	};
	fd = open("/proc/xen/privcmd",O_RDWR);
	if (fd<0){
			perror("cannot open privcmd");
			return 0;
	}
	ret=ioctl(fd,IOCTL_PRIVCMD_HYPERCALL, &unset_cover);
	if (ret < 0 )
		perror("no!");			
	close(fd);
    return 0;

}




