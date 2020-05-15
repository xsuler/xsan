#include <sys/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>
#include <xenctrl.h>
#include <xen/sys/privcmd.h>
#include <errno.h>
#include <xen/xen.h>
#define INT_MAX 2147483647
#define INT_MIN (-INT_MAX - 1)
#define SHIFT 6
#define MASK 0x3f
int main(void){
	int fd, covFd;
	int ret, tmp, count;
	char* fn;  
        long long int cover[5000] = {0};
	int pc[5000*32];
	privcmd_hypercall_t set_cover={
			__HYPERVISOR_set_cov_array,
			{(long long int)&cover,0,0,0,0}
	}; 
	fd = open("/proc/xen/privcmd",O_RDWR);
	if (fd<0){
			perror("cannot open privcmd");
			return 0;
	}
	ret = ioctl(fd,IOCTL_PRIVCMD_HYPERCALL, &set_cover); 
	if (ret <  0)
	{
		printf("-------------failed!\n\n");
		return 0;
	}
	count = 0;
	fn = "/dev/cov";
	for (int i = 0; i < 5000; ++i )
	{
	
//		printf("%d---\n", i);
		if (cover[i] == 0)
			continue;
//		if (cover[i] < 0)
//			cover[i] += (~INT_MIN);
			
		for (int j = 0; j < 32; ++j)
		{
			if (cover[i] & (1 << j))
			{
				pc[count++] = i*32+j;
			}
		/*	int n = i*32+j;
			
			if (cover[n>>SHIFT] & (1<<(n&MASK)) )
			{
				pc[count++] = i*32+j;
				printf("pc = %d\t", i*32+j);
			}	
	i*/	}
	}
	covFd= open(fn, O_RDWR);

	if (covFd == -1) {
		creat(fn, 0777);
		covFd = open(fn, O_RDWR);
	}
	write(covFd, pc, sizeof(pc));
	close(covFd);
	close(fd);
	return 0;

}




