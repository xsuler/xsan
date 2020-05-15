#include <sys/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>
#include <xenctrl.h>
#include <xen/sys/privcmd.h>
#include <errno.h>
#include <xen/xen.h>
#include <libexplain/ioctl.h>


int main(int argc, char** argv){
        int fd;
	int ret=0;
	FILE *fp;
	if((fp=fopen("/dev/fault","r"))==NULL){
		printf("file cannot be opened");
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	int fsize = (int)ftell(fp);
	fseek(fp,0,SEEK_SET);

	char* str = malloc(fsize+1);
	fread(str,1,fsize,fp);


	fclose(fp);
	str[fsize]=0;
	int buf[100]={0};
	int n=0;
	for(int i=0;i<fsize/4;i++){
		buf[n++]=*(int*)(str+i*4);
	}

	printf("setting fault : %d",buf[0]);
        privcmd_hypercall_t my_hypercall={
                __HYPERVISOR_set_fault,
                {(long long int)buf,0,0,0,0}
        };
        fd = open("/proc/xen/privcmd",O_RDWR);
        if (fd<0){
                perror("cannot open privcmd");
                return 0;
        }
        ret=ioctl(fd,IOCTL_PRIVCMD_HYPERCALL, &my_hypercall);
	free(str);
        return 0;

}



