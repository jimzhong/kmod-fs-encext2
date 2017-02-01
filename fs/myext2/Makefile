#
# Makefile for the linux myext2-filesystem routines.
#

obj-m += myext2.o

myext2-y := balloc.o dir.o file.o ialloc.o inode.o \
	  ioctl.o namei.o super.o symlink.o

KDIR := /home/jimzhong/linux-4.8.7
PWD := $(shell pwd)
default:
	make -C $(KDIR) M=$(PWD) modules
