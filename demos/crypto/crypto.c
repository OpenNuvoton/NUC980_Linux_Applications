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
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "if_alg.h"


#ifndef AF_ALG
#define AF_ALG      38
#endif

#ifndef SOL_ALG
#define SOL_ALG     279
#endif

#define BUF_SIZE    512


static void aes_crypt(__u8 *protocol, int encrypt, 
							char *in, int inlen, char *out, const char *key, char *oiv)
{
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
	.salg_family = AF_ALG,
	.salg_type = "skcipher",
	.salg_name = "ecb(aes)"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {};
	struct af_alg_iv *iv;
	struct iovec iov;
	
	strcpy(sa.salg_name, protocol);

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
	
	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, 32);
	
	opfd = accept(tfmfd, NULL, 0);
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	
	if (encrypt)
		*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT; 
	else
		*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT; 
 
	cmsg = CMSG_NXTHDR(&msg, cmsg); 
	cmsg->cmsg_level = SOL_ALG; 
	cmsg->cmsg_type = ALG_SET_IV; 
	cmsg->cmsg_len = CMSG_LEN(20); 
	iv = (void *)CMSG_DATA(cmsg); 
	memcpy(iv->iv, oiv, 16);
	iv->ivlen = 16;
	iov.iov_base = in;
	iov.iov_len = inlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sendmsg(opfd, &msg, 0);
	read(opfd, out, inlen);
	close(opfd);
	close(tfmfd);
}


void  print_data(char *str, char *buff, int len)
{
	int  i;
	
	printf("%s: ", str);
	for (i = 0; i < len; i++) 
	 printf("%02x", (unsigned char)buff[i]);
	printf("\n");
}


void AES_demo(void)
{
	int i;
	char out[BUF_SIZE];
	char in[BUF_SIZE];
	const char key[32] =  "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
							"\x51\x2e\x03\xd5\x34\x12\x00\x06"
						   "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
							"\x51\x2e\x03\xd5\x34\x12\x00\x06";
	char iv[16] = "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41";

	printf("\n+---------------------------------------------------------------+\n");
	printf("|  [AF_ALG] AES-256 CBC mode encrypt/descrpt demo               |\n");
	printf("+---------------------------------------------------------------+\n");
	
	for (i = 0; i < BUF_SIZE; i++)
		in[i] = i & 0xff;

	aes_crypt("cbc(aes)", 1, in, BUF_SIZE, out, key, iv);

	printf("\nAES encrypt result =>\n");
	print_data("IN", in, BUF_SIZE);
	print_data("OUT", out, BUF_SIZE);

	aes_crypt("cbc(aes)", 0, out, BUF_SIZE, in, key, iv);

	printf("\nAES descrypt result =>\n");
	print_data("IN", out, BUF_SIZE);
	print_data("OUT", in, BUF_SIZE);
}

int SHA_demo(int digest_size, int is_hmac)
{
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1"
	};
	char msg1[] = { 0xdf, 0x4b, 0xd2 };              // bf36ed5d74727dfd5d7854ec6b1d49468d8ee8aa
	char msg2[] = { 0xf7, 0xfb, 0x1b, 0xe2, 0x05 };  // 60b7d5bb560a1acf6fa45721bd0abb419a841a89
	char msg3[] = { 0x7e, 0x3d, 0x7b, 0x3e, 0xad, 0xa9, 0x88, 0x66 };  // 24a2c34b976305277ce58c2f42d5092031572520
	char hmac_key[8] = { 0x89, 0x11, 0x32, 0xef, 0x10, 0x8a, 0x22, 0x90 };
	char buf[64];
	int  i, bytes;

	printf("\n+---------------------------------------------------------------+\n");
	if (is_hmac)
		printf("|  [AF_ALG] HMAC-SHA-%d demo                                   |\n", digest_size);
	else    
		printf("|  [AF_ALG] SHA-%d demo                                        |\n", digest_size);
	printf("+---------------------------------------------------------------+\n");

	switch (digest_size)
	{
		case 160:
			strcpy(sa.salg_name, is_hmac ? "hmac-sha1" : "sha1");
			break;
			
		case 224:
			strcpy(sa.salg_name, is_hmac ? "hmac-sha224" : "sha224");
			break;

		case 256:
			strcpy(sa.salg_name, is_hmac ? "hmac-sha256" : "sha256");
			break;

		case 384:
			strcpy(sa.salg_name, is_hmac ? "hmac-sha384" : "sha384");
			break;

		case 512:
			strcpy(sa.salg_name, is_hmac ? "hmac-sha512" : "sha512");
			break;
		
		default:
			printf("Invalid parameter!\n");
			return -1;
	}
	
	bytes = digest_size/8;
 
	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
 
	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	opfd = accept(tfmfd, NULL, 0);

	if (is_hmac)
		setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, hmac_key, 8);  // must be x4 length

	write(opfd, msg1, sizeof(msg1));
	read(opfd, buf, bytes);
	printf("Output digest:\n  "); 
	for (i = 0; i < bytes; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");

	if (is_hmac)
		setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, hmac_key, 8);  // must be x4 length

	write(opfd, msg2, sizeof(msg2));
	read(opfd, buf, bytes);
	printf("Output digest:\n  "); 
	for (i = 0; i < bytes; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");

	if (is_hmac)
		setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, hmac_key, 8);  // must be x4 length

	write(opfd, msg3, sizeof(msg3));
	read(opfd, buf, bytes);
	printf("Output digest:\n  "); 
	for (i = 0; i < bytes; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");
 
	close(opfd);
	close(tfmfd);
}

extern void crypto_raw_demo(void);

int main(int argc, char **argv)
{
	AES_demo();
	SHA_demo(160, 0);       // SHA-1
	SHA_demo(160, 1);       // HMAC-SHA-1
	SHA_demo(224, 0);       // SHA-224
	SHA_demo(224, 1);       // HMAC-SHA-224
	SHA_demo(256, 0);       // SHA-256
	SHA_demo(256, 1);       // HMAC-SHA-256
	SHA_demo(384, 0);       // SHA-384
	SHA_demo(384, 1);       // HMAC-SHA-384
	SHA_demo(512, 0);       // SHA-512
	SHA_demo(512, 1);       // HMAC-SHA-512
	
	crypto_raw_demo();
}



