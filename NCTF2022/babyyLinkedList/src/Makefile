obj-m := babyyLinkedList.o

KERNELDR := /home/f101/桌面/kernel/linux-5.4.98

PWD := $(shell pwd)  

modules:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules  

moduels_install:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules_install  

clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
