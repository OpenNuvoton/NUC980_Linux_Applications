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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "nuc980-etimer.h"

int main(int argc, char **argv)
{
	int fd[4], i, j, mode = TMR_CAP_EDGE_FF;
	fd_set rfd;
	struct timeval tv;
	unsigned int cap, cnt;
	int ret;
	unsigned int isrcnt = 0;
	char dev[6][14] = {"/dev/timer0",
	                   "/dev/timer1",
	                   "/dev/timer2",
	                   "/dev/timer3"
	                  };
	int period[4] = {1000, 800, 600, 400};	// Period (in us) of 4 timer channels
	int wkperiod[4] = {16384, 32768, 65536, 163840};
	int timeout = 1000000;  // 1 sec
	int eventcnt = 10;

	for(i = 0; i < 4; i++) {
		fd[i] = open(&dev[i][0], O_RDWR);

		if(fd[i] < 0)
			printf("open etimer %d error\n", i);

		printf("Channel %d Time-out Wakeup testing\n", i);
		// switch clock, power down mode using 32kHz
		ioctl(fd[i], TMR_IOC_CLKLXT, NULL);

		ret = ioctl(fd[i], TMR_IOC_PERIODIC_FOR_WKUP, &wkperiod[i]);
		if(ret == -1)
			printf("clock source error\n");
		else {
			system("echo mem > /sys/power/state");
			printf("Wake up from Timer%d.\n",i);
			printf("hit any key to test next channel\n");
			getchar();
			ioctl(fd[i], TMR_IOC_STOP, NULL);
		}
	}
	printf("hit any key to quit periodic wake-up mode\n");
	getchar();

	//switch clock 12MHz
	for(i = 0; i < 4; i++) {
		ioctl(fd[i], TMR_IOC_CLKHXT, NULL);
	}

	//Periodic demo
	for(i = 0; i < 4; i++) {
		printf("Channel %d Periodic testing\n", i);
		ioctl(fd[i], TMR_IOC_PERIODIC, &timeout);
		for(j = 0; j < 5; j++) {
			read(fd[i], &cnt, sizeof(cnt));
			printf("%d sec\n", cnt);
		}
		ioctl(fd[i], TMR_IOC_STOP, NULL);
	}
	printf("hit any key to quit periodic mode\n");
	getchar();

	// Toggle output demo
	for(i = 0; i < 4; i++) {
		ioctl(fd[i], TMR_IOC_TOGGLE, &period[i]);
	}
	printf("hit any key to quit toggle mode\n");
	getchar();

	//Event counting demo
	for(i = 0; i < 4; i++) {
		printf("Channel %d Event count testing\n", i);
		ioctl(fd[i], TMR_IOC_EVENT_COUNTING, &eventcnt);
		for(j = 0; j < 5; j++) {
			read(fd[i], &cnt, sizeof(cnt));
			printf("Generate falling event. Count %d\n", cnt);
		}
		printf("hit any key to test next channel\n");
		getchar();
		ioctl(fd[i], TMR_IOC_STOP, NULL);
	}
	printf("hit any key to quit event count mode\n");
	getchar();

	// Free counting mode, block
	for(i = 0; i < 4; i++) {
		printf("Channel %d capture testing\n", i);
		ioctl(fd[i], TMR_IOC_FREE_COUNTING, &mode);
		for(j = 0; j < 10; j++) {
			read(fd[i], &cap, sizeof(cap));
			printf("cap:%d Hz\n", cap);
		}
		printf("hit any key to test next channel\n");
		getchar();
		ioctl(fd[i], TMR_IOC_STOP, NULL);
	}

	printf("hit any key to quit free counting mode\n");
	getchar();

	// Trigger counting mode, block
	for(i = 0; i < 4; i++) {
		printf("Channel %d capture testing\n", i);
		ioctl(fd[i], TMR_IOC_TRIGGER_COUNTING, &mode);
		for(j = 0; j < 10; j++) {
			read(fd[i], &cap, sizeof(cap));
			printf("cap:%d us\n", cap);
		}
		printf("hit any key to test next channel\n");
		getchar();
		ioctl(fd[i], TMR_IOC_STOP, NULL);
	}

	// Trigger counting mode, polling
	for(i = 0; i < 4; i++) {
		FD_ZERO(&rfd);
		FD_SET(fd[i], &rfd);

		printf("Channel %d capture poll testing\n", i);
		ioctl(fd[i], TMR_IOC_TRIGGER_COUNTING, &mode);

		for(j = 0; j < 10; j++) {
			ret = select(fd[i] + 1, &rfd, NULL, NULL, NULL);
			if(ret == -1) {
				printf("select error\n");
			} else if(FD_ISSET(fd[i], &rfd)) {

				read(fd[i], &cap, sizeof(cap));
				printf("cap:%d us\n", cap);
			}
		}
		printf("hit any key to test next channel\n");
		getchar();
		ioctl(fd[i], TMR_IOC_STOP, NULL);
	}

	close(fd[0]);
	close(fd[1]);
	close(fd[2]);
	close(fd[3]);

	return 0;
}
