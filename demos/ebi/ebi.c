/*
 * Copyright (c) 2018 Nuvoton technology corporation
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/ioctl.h>
#include <sys/mman.h>
#include "nuc980-ebi.h"



int main(int argc, char **argv)
{
	int fd,i,j;
	unsigned char *pEbiBuffer;
	unsigned long uEbiSize;
	unsigned int patterns[4]= {0x00000000,0x55555555,0xAAAAAAAA,0xFFFFFFFF};
	struct nuc980_set_ebi ebi;


	fd = open("/dev/ebi",O_RDWR);
	if(fd < 0)
		printf("open ebi error\n");

	ebi.bank = 0;
	ebi.base = 0x60000000;
	//ebi.bank = 1;
	//ebi.base = 0x60100000;
	//ebi.bank = 2;
	//ebi.base = 0x60200000;
	ebi.busmode = EBI_OPMODE_NORMAL;
	ebi.CSActiveLevel = EBI_CS_ACTIVE_LOW;
	ebi.width = EBI_BUSWIDTH_16BIT;
	ebi.timing = EBI_TIMING_SLOWEST;
	ioctl(fd, EBI_IOC_SET, &ebi);

	uEbiSize = 2 * 1024 ; //2K
	pEbiBuffer = mmap(NULL, uEbiSize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (pEbiBuffer == MAP_FAILED) {
		printf("mmap() failed\n");
		exit(0);
	}


#if(1)	//Word Write/Read
	printf("Start to Read/Write test\n");
	for(i=0; i<uEbiSize; i+=4) {
		unsigned int tmp;
		for(j=0; j<4; j++) {
			*(unsigned int *)(pEbiBuffer+i)=patterns[j];
			tmp=*(unsigned int *)(pEbiBuffer+i);
			if(tmp!=patterns[j]) {
				printf("Read/Write test failed, patterns=0x%08x, data[%d]=0x%08x\n",patterns[j],i,*(unsigned int*)(pEbiBuffer+i));
				return 0;
			}
		}
	}
#else //Byte Write/Read
	printf("Start to Read/Write test\n");
	char tmp;
	for(i=0; i<uEbiSize; i++) {
		*(char *)(pEbiBuffer+i)=(char)i;
		tmp=*(char *)(pEbiBuffer+i);
		if(tmp!=(char)i) {
			printf("Read/Write test failed, patterns=0x%08x, data[%d]=0x%08x\n",(char)i,i,*(char*)(pEbiBuffer+i));
			return 0;
		}
	}
#endif

	printf("Compare data passed\n");
	close(fd);
	return 0;
}
