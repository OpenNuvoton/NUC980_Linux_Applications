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

#include <sys/mman.h>
#include <sys/stat.h>

#include "nuc980-crypto.h"

#define BUF_SIZE    1024


#define NVT_AES          "/dev/nuvoton-aes"
#define NVT_SHA          "/dev/nuvoton-sha"
#define NVT_ECC          "/dev/nuvoton-ecc"
#define NVT_RSA          "/dev/nuvoton-rsa"

int   fd_aes = -1;
int   fd_sha = -1;
int   fd_ecc = -1;

unsigned char  *aes_map_inbuff, *aes_map_outbuff;
unsigned long  aes_buff_size;

extern void  print_data(char *str, char *buff, int len);


int Nuvoton_Init_AES(void)
{
	fd_aes = open(NVT_AES, O_RDWR);
	if (fd_aes < 0) 
	{
		printf("open %s error\n", NVT_AES);
		return fd_aes;
	}

	if (ioctl(fd_aes, AES_IOC_GET_BUFSIZE, &aes_buff_size) < 0)
	{
		printf("Failed to get Nuvoton AES buffer size!\n");
		close(fd_aes);
		fd_aes = -1;
		return -1;
	}

    aes_map_inbuff = (unsigned char *)mmap(NULL, aes_buff_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_aes, 0);
    if (aes_map_inbuff == NULL)
    {
		printf("Failed to mmap AES buffer!\n");
		close(fd_aes);
		fd_aes = -1;
		return -1;
    }
    aes_map_outbuff = aes_map_inbuff + aes_buff_size/2;
    printf("Nuvoton AES buffer size %d, map to 0x%x.\n", (int)aes_buff_size, (int)aes_map_inbuff);
	return 0;
}

void Nuvoton_Deinit_AES(void)
{
   	munmap(aes_map_inbuff, aes_buff_size);
   	close(fd_aes);
}

static void aes_crypt(int encrypt, char *in, int len, char *out, const char *key, char *iv)
{
    size_t          dma_size;
    unsigned long   mode;
    
    dma_size = (size_t)(aes_buff_size / 2);

    mode = NVT_AES_INSWAP | NVT_AES_OUTSWAP | NVT_AES_KEYSZ_256 | NVT_AES_CBC_MODE;
    
   	if (encrypt)
   	    mode |= NVT_AES_ENCRYPT;
   	else
   	    mode |= NVT_AES_DECRYPT;
	
    ioctl(fd_aes, AES_IOC_SET_MODE, mode);
    ioctl(fd_aes, AES_IOC_SET_IV, (unsigned long *)iv);
    ioctl(fd_aes, AES_IOC_SET_KEY, key);

    if (len < dma_size)
    {
    	memcpy(aes_map_inbuff, in, len);
    	ioctl(fd_aes, AES_IOC_SET_LEN, len);
    	ioctl(fd_aes, AES_IOC_START, 1);
    	memcpy(out, aes_map_outbuff, len);
    	len = 0;
    }
    else
    {
    	memcpy(aes_map_inbuff, in, dma_size);
    	ioctl(fd_aes, AES_IOC_SET_LEN, dma_size);
    	ioctl(fd_aes, AES_IOC_START, 1);
    	memcpy(out, aes_map_outbuff, dma_size);
    	len -= dma_size;
    	in += dma_size;
    	out += dma_size;
    }
    
    while (len > 0)
    {
    	if (len < dma_size)
    	{
    		memcpy(aes_map_inbuff, in, len);
    		ioctl(fd_aes, AES_IOC_SET_LEN, len);
    		ioctl(fd_aes, AES_IOC_C_START, 1);
    		memcpy(out, aes_map_outbuff, len);
    		len = 0;
    	}
    	else
	    {
	    	memcpy(aes_map_inbuff, in, dma_size);
	    	ioctl(fd_aes, AES_IOC_SET_LEN, dma_size);
	    	ioctl(fd_aes, AES_IOC_C_START, 1);
	    	memcpy(out, aes_map_outbuff, dma_size);
	    	len -= dma_size;
	    	in += dma_size;
	    	out += dma_size;
	    }
	}
}

void AES_raw_demo(void)
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
	printf("|  [RAW] AES-256 CBC mode encrypt/descrpt demo                  |\n");
	printf("+---------------------------------------------------------------+\n");

	for (i = 0; i < BUF_SIZE; i++)
		in[i] = (i ^ 0xff) & 0xff;

	aes_crypt(1, in, BUF_SIZE, out, key, iv);

	printf("\nAES encrypt result =>\n");
	print_data("IN", in, BUF_SIZE);
	print_data("OUT", out, BUF_SIZE);

	aes_crypt(0, out, BUF_SIZE, in, key, iv);

	printf("\nAES descrypt result =>\n");
	print_data("IN", out, BUF_SIZE);
	print_data("OUT", in, BUF_SIZE);
}

int Nuvoton_Init_SHA(void)
{
	fd_sha = open(NVT_SHA, O_RDWR);
	if (fd_sha < 0) 
	{
		printf("open %s error\n", NVT_SHA);
		return fd_sha;
	}
	return 0;
}

void Nuvoton_Deinit_SHA(void)
{
   	close(fd_sha);
}

int SHA_raw_demo(void)
{
	int i;
	char in[BUF_SIZE];
	unsigned char  msg_dgst[66];
	
	for (i = 0; i < BUF_SIZE; i++)
		in[i] = i & 0xff;

	printf("\n+---------------------------------------------------------------+\n");
	printf("|  [RAW] SHA256 demo                                            |\n");
	printf("+---------------------------------------------------------------+\n");
	
	ioctl(fd_sha, SHA_IOC_INIT, NVT_SHA256 | NVT_SHA_INSWAP | NVT_SHA_OUTSWAP);
	write(fd_sha, in, BUF_SIZE);
	ioctl(fd_sha, SHA_IOC_FINISH, 1);
	memset(msg_dgst, 0, sizeof(msg_dgst));
	read(fd_sha, msg_dgst, 32);
	printf("\nSHA digest: ");
	for (i = 0; i < 32; i++)
		printf("%02x", msg_dgst[i]);
	printf("\n\n");
	return 0;
}

int Nuvoton_Init_ECC(void)
{
	fd_ecc = open(NVT_ECC, O_RDWR);
	if (fd_ecc < 0) 
	{
		printf("open %s error\n", NVT_ECC);
		return fd_ecc;
	}
	return 0;
}

void Nuvoton_Deinit_ECC(void)
{
   	close(fd_ecc);
}

int ECC_raw_demo(void)
{
	int i;
	char  d[168], Qx[168], Qy[168];
	char  msg[168], k[168], R[168], S[168], r[168], s[168];

	printf("\n+---------------------------------------------------------------+\n");
	printf("|  [RAW] ECC key generation demo                                |\n");
	printf("+---------------------------------------------------------------+\n");
	
	/* NIST P-256 test vector */
	/* private key: c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357
	   public key1: d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f
	   public key2: 9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f
	*/
	memset(Qx, 0, sizeof(Qx));	
	memset(Qy, 0, sizeof(Qy));	
	strcpy(d, "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357");
	ioctl(fd_ecc, ECC_IOC_SEL_CURVE, ECC_CURVE_P_256);
	ioctl(fd_ecc, ECC_IOC_SET_PRI_KEY, d);
	ioctl(fd_ecc, ECC_IOC_GEN_PUB_KEY, 0);
	
	ioctl(fd_ecc, ECC_IOC_GET_PUB_K1, Qx);
	ioctl(fd_ecc, ECC_IOC_GET_PUB_K2, Qy);
	printf("\nP-256 private key: %s\n", d);
	printf("public key 1: %s\n", Qx);
	printf("public key 2: %s\n", Qy);
	
	/* NIST K-571 test vector */
	/* private key: 78c55b165683df3d44e66eacc650cc56069b4ad0fb267cc1fb30c026ee6ceded772b527458e99252f5740da681eb9c82cdd9efc57614aa448e9d2dae48e0393cfb028591cdc03e
	   public key1: 7a1e3910d02ad1c34159b890cdad01f745f5e0e8726b632028b009ecc8073b5d8463960b3310ca83798866f8f025beddfde8019cc4e66cfcba6f03453368daaeefcb4fdc1ea4ac1
	   public key2: 585981805ee26c54baeec9fb737d63e083b782275cc3a842425c2765f7898a498b010faa2a39a39bf775def6e868a6b108f04009d974df3754e9a951b39eb0bff4a6ec4368e4214
	*/
	memset(Qx, 0, sizeof(Qx));	
	memset(Qy, 0, sizeof(Qy));	
	strcpy(d, "78c55b165683df3d44e66eacc650cc56069b4ad0fb267cc1fb30c026ee6ceded772b527458e99252f5740da681eb9c82cdd9efc57614aa448e9d2dae48e0393cfb028591cdc03e");
	ioctl(fd_ecc, ECC_IOC_SEL_CURVE, ECC_CURVE_K_571);
	ioctl(fd_ecc, ECC_IOC_SET_PRI_KEY, d);
	ioctl(fd_ecc, ECC_IOC_GEN_PUB_KEY, 0);
	
	ioctl(fd_ecc, ECC_IOC_GET_PUB_K1, Qx);
	ioctl(fd_ecc, ECC_IOC_GET_PUB_K2, Qy);
	printf("\n\nK-571 private key: %s\n", d);
	printf("public key 1: %s\n", Qx);
	printf("public key 2: %s\n", Qy);


	printf("\n+---------------------------------------------------------------+\n");
	printf("|  [RAW] ECDSA signature generation                             |\n");
	printf("+---------------------------------------------------------------+\n");

	/* NIST ECDSA P-256 test vector */
	/* message digest: a3f91ae21ba6b3039864472f184144c6af62cd0e
	   private key:    be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25
	   public key 1:   fa2737fb93488d19caef11ae7faf6b7f4bcd67b286e3fc54e8a65c2b74aeccb0
	   public key 2:   d4ccd6dae698208aa8c3a6f39e45510d03be09b2f124bfc067856c324f9b4d09
	   random number:  18731ef637fe84872cf89a879567946a50f327f3af3aaeb6074a86f117e332b0
	   Signature R:    2b826f5d44e2d0b6de531ad96b51e8f0c56fdfead3c236892e4d84eacfc3b75c
	   Signature S:    a2248b62c03db35a7cd63e8a120a3521a89d3d2f61ff99035a2148ae32e3a248
	*/

	memset(Qx, 0, sizeof(Qx));	
	memset(Qy, 0, sizeof(Qy));	
	strcpy(d, "be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25");
	ioctl(fd_ecc, ECC_IOC_SEL_CURVE, ECC_CURVE_P_256);
	ioctl(fd_ecc, ECC_IOC_SET_PRI_KEY, d);
	ioctl(fd_ecc, ECC_IOC_GEN_PUB_KEY, 0);
	
	ioctl(fd_ecc, ECC_IOC_GET_PUB_K1, Qx);
	ioctl(fd_ecc, ECC_IOC_GET_PUB_K2, Qy);

	strcpy(msg, "a3f91ae21ba6b3039864472f184144c6af62cd0e");
	strcpy(d, "be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25");
	strcpy(k, "18731ef637fe84872cf89a879567946a50f327f3af3aaeb6074a86f117e332b0");
	
	ioctl(fd_ecc, ECC_IOC_SEL_CURVE, ECC_CURVE_P_256);
	ioctl(fd_ecc, ECC_IOC_SET_PRI_KEY, d);
	ioctl(fd_ecc, ECC_IOC_SET_RANDOM_K, k);
	ioctl(fd_ecc, ECC_IOC_SET_MSG, msg);
	ioctl(fd_ecc, ECC_IOC_ECDSA_SIGN, 0);
	
	memset(R, 0, sizeof(R));	
	memset(S, 0, sizeof(S));	
	ioctl(fd_ecc, ECC_IOC_GET_SIG_R, R);
	ioctl(fd_ecc, ECC_IOC_GET_SIG_S, S);
	printf("Output Signature R: %s\n", R);
	printf("Output Signature S: %s\n", S);
	
	printf("\n+---------------------------------------------------------------+\n");
	printf("|  [RAW] ECDSA signature verification                             |\n");
	printf("+---------------------------------------------------------------+\n");

	printf("message digest: %s\n", msg);
	printf("public key 1:   %s\n", Qx);
	printf("public key 2:   %s\n", Qy);
	printf("Signature R:    %s\n", R);
	printf("Signature S:    %s\n", S);
	
	ioctl(fd_ecc, ECC_IOC_SEL_CURVE, ECC_CURVE_P_256);
	ioctl(fd_ecc, ECC_IOC_SET_MSG, msg);
	ioctl(fd_ecc, ECC_IOC_SET_PUB_K1, Qx);
	ioctl(fd_ecc, ECC_IOC_SET_PUB_K2, Qy);
	ioctl(fd_ecc, ECC_IOC_SET_SIG_R, R);
	ioctl(fd_ecc, ECC_IOC_SET_SIG_S, S);
	
	printf("Signature verification result: %s\n", ioctl(fd_ecc, ECC_IOC_ECDSA_VERIFY, 0) == 0 ? "[PASS]" : "[FAIL]");
	return 0;
}

void crypto_raw_demo(void)
{
	/* AES */
	if (Nuvoton_Init_AES() != 0)
		return;
	AES_raw_demo();
	Nuvoton_Deinit_AES();
	
	/* SHA */
	if (Nuvoton_Init_SHA() != 0)
		return;
	SHA_raw_demo();
	Nuvoton_Deinit_SHA();

	/* ECC */
	if (Nuvoton_Init_ECC() != 0)
		return;
	ECC_raw_demo();
	Nuvoton_Deinit_ECC();
}



