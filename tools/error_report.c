#include <sys/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>
#include <xenctrl.h>
#include <xen/sys/privcmd.h>
#include <errno.h>
#include <xen/xen.h>

struct err_trace
{
	int id;
	void* xasan_err_addr;
	int64_t xasan_err_size;
	int xasan_err_type;
	int xasan_ord;
	int xasan_shadow;
	char xasan_trace[20][100]; 
	int xasan_trace_pos; 
	int is_write;
};



int main(int argc, char** argv){
        int fd;
        int ret;
        ret=0;
        long long int fault=0;
        struct err_trace e;
	e.id=0;
	e.xasan_err_addr=0;
	if(argc>1)
		e.id=atoi(argv[1]);
        privcmd_hypercall_t my_hypercall={
                __HYPERVISOR_get_trace,
                {(long long int)&e,0,0,0,0}
        };

        fd = open("/proc/xen/privcmd",O_RDWR);
        if (fd<0){
                perror("cannot open privcmd");
                return 0;
        }
        ret=ioctl(fd,IOCTL_PRIVCMD_HYPERCALL, &my_hypercall);
	char err_info[20];
	char io_type[10];
	char trace[1024];
	strcpy(io_type,"read");
	if(e.is_write)
		strcpy(io_type,"write");
	int flag=0;
	if(e.xasan_err_type==0){
		flag=1;
		strcpy(err_info,"global variable overflow");
	}
	if(e.xasan_err_type==119){
		flag=1;
		strcpy(err_info,"double free");
	}

	if(e.xasan_err_type==120){
		flag=1;
		strcpy(err_info,"heap overflow");
	}
	if(e.xasan_err_type==121){
		flag=1;
		strcpy(err_info,"use after free");
	}
	if(e.xasan_err_type==122){
		flag=1;
		strcpy(err_info,"stack overflow");
	}
	if(e.xasan_err_type==123){
		flag=1;
		strcpy(err_info,"use after return");
	}
	if(e.xasan_err_type==124){
		flag=1;
		strcpy(err_info,"uninitialized memory read");
	}

	if(flag==0)
		return 0;

	int pos=0;
	for(int i=e.xasan_trace_pos;i>=0;i--){
		trace[pos]='\t';
		pos+=1;
		strcpy((char*)trace+pos,e.xasan_trace[i]);
		pos+=strlen(e.xasan_trace[i]);
		strcpy((char*)trace+pos,"\n");
		pos+=1;
	}
	trace[pos]=0;
	if(e.xasan_err_addr!=0)
		printf("====ERROR: XenSanitizer: %s on address %p\n%s of size %ld at %p\n%s\n",err_info,e.xasan_err_addr, io_type, e.xasan_err_size,e.xasan_err_addr,trace);

        return 0;

}



