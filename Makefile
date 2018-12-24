# http://www.mjmwired.net/kernel/Documentation/kbuild/modules.txt

#obj-y += main.o
custom_module-y += utils.o memutils.o main.o
obj-m += custom_module.o
ccflags-y += -Ofast -Wall -masm=intel #*-Wa,-a,-ad
#EXTRA_CFLAGS = -I/home/kamay/github/memory-manager

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean