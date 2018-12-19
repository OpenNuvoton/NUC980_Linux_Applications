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
int   fd_rsa = -1;

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
	ioctl(fd_ecc, ECC_IOC_SET_SCALAR_K, k);
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


/*-----------------------------------------------------------------------------------------------*/
/*                                                                                               */
/*    RSA                                                                                        */
/*                                                                                               */
/*-----------------------------------------------------------------------------------------------*/

#define RSA_MAX_KLEN      (2048)
#define RSA_KBUF_HLEN     (RSA_MAX_KLEN/4 + 8)
#define RSA_KBUF_BLEN     (RSA_MAX_KLEN + 32)

#define MAX_DIGIT         0xFFFFFFFFUL
#define MAX_HALF_DIGIT    0xFFFFUL  /* NB 'L' */
#define BITS_PER_DIGIT    32
#define HIBITMASK         0x80000000UL

#define MAX_FIXED_BIT_LENGTH    8192
#define MAX_FIXED_DIGITS        ((MAX_FIXED_BIT_LENGTH + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT)

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

static unsigned int   qq[MAX_FIXED_DIGITS*2];
static unsigned int   rr[MAX_FIXED_DIGITS*2];


/** Returns number of significant digits in a */
static int mpSizeof(const unsigned int a[], int ndigits)
{       
	while (ndigits--)
	{
		if (a[ndigits] != 0)
			return (++ndigits);
	}
	return 0;
}


static int  mpBitLength(const unsigned int d[], int ndigits)
/* Returns no of significant bits in d */
{
	int        n, i, bits;
	unsigned int   mask;

	if (!d || ndigits == 0)
		return 0;

	n = mpSizeof(d, ndigits);
	if (0 == n) return 0;

	for (i = 0, mask = HIBITMASK; mask > 0; mask >>= 1, i++)
	{
		if (d[n-1] & mask)
			break;
	}
	bits = n * BITS_PER_DIGIT - i;
	return bits;
}

static int mpGetBit(const unsigned int a[], int ndigits, int ibit)
	/* Returns value 1 or 0 of bit n (0..nbits-1); or -1 if out of range */
{
	int       idigit, bit_to_get;
	unsigned int  mask;

	/* Which digit? (0-based) */
	idigit = ibit / BITS_PER_DIGIT;
	if (idigit >= ndigits)
		return -1;

	/* Set mask */
	bit_to_get = ibit % BITS_PER_DIGIT;
	mask = 0x01 << bit_to_get;

	return ((a[idigit] & mask) ? 1 : 0);
}

static unsigned int mpSetZero(volatile unsigned int a[], int ndigits)
{   /* Sets a = 0 */

	/* Prevent optimiser ignoring this */
	volatile unsigned int optdummy;
	volatile unsigned int *p = a;

	while (ndigits--)
		a[ndigits] = 0;
	
	optdummy = *p;
	return optdummy;
}

static void mpSetEqual(unsigned int a[], const unsigned int b[], int ndigits)
{   /* Sets a = b */
	int i;
	
	for (i = 0; i < ndigits; i++)
	{
		a[i] = b[i];
	}
}

static void mpSetDigit(unsigned int a[], unsigned int d, int ndigits)
{   /* Sets a = d where d is a single digit */
	int i;
	
	for (i = 1; i < ndigits; i++)
	{
		a[i] = 0;
	}
	a[0] = d;
}

/** Returns sign of (a - b) as 0, +1 or -1. Not constant-time. */
static int mpCompare(const unsigned int a[], const unsigned int b[], int ndigits)
{
	/* if (ndigits == 0) return 0; // deleted [v2.5] */

	while (ndigits--)
	{
		if (a[ndigits] > b[ndigits])
			return 1;   /* GT */
		if (a[ndigits] < b[ndigits])
			return -1;  /* LT */
	}

	return 0;   /* EQ */
}

static unsigned int mpShiftLeft(unsigned int a[], const unsigned int *b,
	int shift, int ndigits)
{   /* Computes a = b << shift */
	/* [v2.1] Modified to cope with shift > BITS_PERDIGIT */
	int i, y, nw, bits;
	unsigned int mask, carry, nextcarry;

	/* Do we shift whole digits? */
	if (shift >= BITS_PER_DIGIT)
	{
		nw = shift / BITS_PER_DIGIT;
		i = ndigits;
		while (i--)
		{
			if (i >= nw)
				a[i] = b[i-nw];
			else
				a[i] = 0;
		}
		/* Call again to shift bits inside digits */
		bits = shift % BITS_PER_DIGIT;
		carry = b[ndigits-nw] << bits;
		if (bits) 
			carry |= mpShiftLeft(a, a, bits, ndigits);
		return carry;
	}
	else
	{
		bits = shift;
	}

	/* Construct mask = high bits set */
	mask = ~(~(unsigned int)0 >> bits);
	
	y = BITS_PER_DIGIT - bits;
	carry = 0;
	for (i = 0; i < ndigits; i++)
	{
		nextcarry = (b[i] & mask) >> y;
		a[i] = b[i] << bits | carry;
		carry = nextcarry;
	}

	return carry;
}

static unsigned int mpShiftRight(unsigned int a[], const unsigned int b[], int shift, int ndigits)
{   /* Computes a = b >> shift */
	/* [v2.1] Modified to cope with shift > BITS_PERDIGIT */
	int i, y, nw, bits;
	unsigned int mask, carry, nextcarry;

	/* Do we shift whole digits? */
	if (shift >= BITS_PER_DIGIT)
	{
		nw = shift / BITS_PER_DIGIT;
		for (i = 0; i < ndigits; i++)
		{
			if ((i+nw) < ndigits)
				a[i] = b[i+nw];
			else
				a[i] = 0;
		}
		/* Call again to shift bits inside digits */
		bits = shift % BITS_PER_DIGIT;
		carry = b[nw-1] >> bits;
		if (bits) 
			carry |= mpShiftRight(a, a, bits, ndigits);
		return carry;
	}
	else
	{
		bits = shift;
	}

	/* Construct mask to set low bits */
	/* (thanks to Jesse Chisholm for suggesting this improved technique) */
	mask = ~(~(unsigned int)0 << bits);
	
	y = BITS_PER_DIGIT - bits;
	carry = 0;
	i = ndigits;
	while (i--)
	{
		nextcarry = (b[i] & mask) << y;
		a[i] = b[i] >> bits | carry;
		carry = nextcarry;
	}

	return carry;
}

static unsigned int spDivide(unsigned int *pq, unsigned int *pr, const unsigned int u[2], unsigned int v)
{
	unsigned long long uu, q;

	uu = (unsigned long long)u[1] << 32 | (unsigned long long)u[0];
	q = uu / (unsigned long long)v;
	*pr = (unsigned int)(uu - q * v);
	*pq = (unsigned int)(q & 0xFFFFFFFF);
	return (unsigned int)(q >> 32);
}

static int spMultiply(unsigned int p[2], unsigned int x, unsigned int y)
{
	/* Use a 64-bit temp for product */
	unsigned long long t = (unsigned long long)x * (unsigned long long)y;
	/* then split into two parts */
	p[1] = (unsigned int)(t >> 32);
	p[0] = (unsigned int)(t & 0xFFFFFFFF);

	return 0;
}

static unsigned int mpMultSub(unsigned int wn, unsigned int w[], const unsigned int v[],
					   unsigned int q, int n)
{   /*  Compute w = w - qv
		where w = (WnW[n-1]...W[0])
		return modified Wn.
	*/
	unsigned int k, t[4];
	int i;

	if (q == 0) /* No change */
		return wn;

	k = 0;

	for (i = 0; i < n; i++)
	{
		spMultiply(t, q, v[i]);
		w[i] -= k;
		if (w[i] > MAX_DIGIT - k)
			k = 1;
		else
			k = 0;
		w[i] -= t[0];
		if (w[i] > MAX_DIGIT - t[0])
			k++;
		k += t[1];
	}

	/* Cope with Wn not stored in array w[0..n-1] */
	wn -= k;

	return wn;
}

static unsigned int mpShortDiv(unsigned int q[], const unsigned int u[], unsigned int v, 
				   int ndigits)
{
	/*  Calculates quotient q = u div v
		Returns remainder r = u mod v
		where q, u are multiprecision integers of ndigits each
		and r, v are single precision digits.

		Makes no assumptions about normalisation.
		
		Ref: Knuth Vol 2 Ch 4.3.1 Exercise 16 p625
	*/
	int j;
	unsigned int t[4], r;
	int shift;
	unsigned int bitmask, overflow, *uu;

	if (ndigits == 0) return 0;
	if (v == 0) return 0;   /* Divide by zero error */

	/*  Normalise first */
	/*  Requires high bit of V
		to be set, so find most signif. bit then shift left,
		i.e. d = 2^shift, u' = u * d, v' = v * d.
	*/
	bitmask = HIBITMASK;
	for (shift = 0; shift < BITS_PER_DIGIT; shift++)
	{
		if (v & bitmask)
			break;
		bitmask >>= 1;
	}

	v <<= shift;
	overflow = mpShiftLeft(q, u, shift, ndigits);
	uu = q;
	
	/* Step S1 - modified for extra digit. */
	r = overflow;   /* New digit Un */
	j = ndigits;
	while (j--)
	{
		/* Step S2. */
		t[1] = r;
		t[0] = uu[j];
		overflow = spDivide(&q[j], &r, t, v);
	}

	/* Unnormalise */
	r >>= shift;
	
	return r;
}

static int QhatTooBig(unsigned int qhat, unsigned int rhat,
					  unsigned int vn2, unsigned int ujn2)
{   /*  Returns true if Qhat is too big
		i.e. if (Qhat * Vn-2) > (b.Rhat + Uj+n-2)
	*/
	unsigned int t[4];

	spMultiply(t, qhat, vn2);
	if (t[1] < rhat)
		return 0;
	else if (t[1] > rhat)
		return 1;
	else if (t[0] > ujn2)
		return 1;

	return 0;
}

static unsigned int mpAdd(unsigned int w[], const unsigned int u[], const unsigned int v[], int ndigits)
{
	/*  Calculates w = u + v
		where w, u, v are multiprecision integers of ndigits each
		Returns carry if overflow. Carry = 0 or 1.

		Ref: Knuth Vol 2 Ch 4.3.1 p 266 Algorithm A.
	*/

	unsigned int k;
	int j;

	// assert(w != v);

	/* Step A1. Initialise */
	k = 0;

	for (j = 0; j < ndigits; j++)
	{
		/*  Step A2. Add digits w_j = (u_j + v_j + k)
			Set k = 1 if carry (overflow) occurs
		*/
		w[j] = u[j] + k;
		if (w[j] < k)
			k = 1;
		else
			k = 0;
		
		w[j] += v[j];
		if (w[j] < v[j])
			k++;

	}   /* Step A3. Loop on j */

	return k;   /* w_n = k */
}

static int mpDivide(unsigned int q[], unsigned int r[], const unsigned int u[],
	int udigits, unsigned int v[], int vdigits)
{   /*  Computes quotient q = u / v and remainder r = u mod v
		where q, r, u are multiple precision digits
		all of udigits and the divisor v is vdigits.

		Ref: Knuth Vol 2 Ch 4.3.1 p 272 Algorithm D.

		Do without extra storage space, i.e. use r[] for
		normalised u[], unnormalise v[] at end, and cope with
		extra digit Uj+n added to u after normalisation.

		WARNING: this trashes q and r first, so cannot do
		u = u / v or v = u mod v.
		It also changes v temporarily so cannot make it const.
	*/
	int shift;
	int n, m, j;
	unsigned int bitmask, overflow;
	unsigned int qhat, rhat, t[4];
	unsigned int *uu, *ww;
	int qhatOK, cmp;

	/* Clear q and r */
	mpSetZero(q, udigits);
	mpSetZero(r, udigits);

	/* Work out exact sizes of u and v */
	n = (int)mpSizeof(v, vdigits);
	m = (int)mpSizeof(u, udigits);
	m -= n;

	/* Catch special cases */
	if (n == 0)
		return -1;  /* Error: divide by zero */

	if (n == 1)
	{   /* Use short division instead */
		r[0] = mpShortDiv(q, u, v[0], udigits);
		return 0;
	}

	if (m < 0)
	{   /* v > u, so just set q = 0 and r = u */
		mpSetEqual(r, u, udigits);
		return 0;
	}

	if (m == 0)
	{   /* u and v are the same length */
		cmp = mpCompare(u, v, (int)n);
		if (cmp < 0)
		{   /* v > u, as above */
			mpSetEqual(r, u, udigits);
			return 0;
		}
		else if (cmp == 0)
		{   /* v == u, so set q = 1 and r = 0 */
			mpSetDigit(q, 1, udigits);
			return 0;
		}
	}

	/*  In Knuth notation, we have:
		Given
		u = (Um+n-1 ... U1U0)
		v = (Vn-1 ... V1V0)
		Compute
		q = u/v = (QmQm-1 ... Q0)
		r = u mod v = (Rn-1 ... R1R0)
	*/

	/*  Step D1. Normalise */
	/*  Requires high bit of Vn-1
		to be set, so find most signif. bit then shift left,
		i.e. d = 2^shift, u' = u * d, v' = v * d.
	*/
	bitmask = HIBITMASK;
	for (shift = 0; shift < BITS_PER_DIGIT; shift++)
	{
		if (v[n-1] & bitmask)
			break;
		bitmask >>= 1;
	}

	/* Normalise v in situ - NB only shift non-zero digits */
	overflow = mpShiftLeft(v, v, shift, n);

	/* Copy normalised dividend u*d into r */
	overflow = mpShiftLeft(r, u, shift, n + m);
	uu = r; /* Use ptr to keep notation constant */

	t[0] = overflow;    /* Extra digit Um+n */

	/* Step D2. Initialise j. Set j = m */
	for (j = m; j >= 0; j--)
	{
		/* Step D3. Set Qhat = [(b.Uj+n + Uj+n-1)/Vn-1] 
		   and Rhat = remainder */
		qhatOK = 0;
		t[1] = t[0];    /* This is Uj+n */
		t[0] = uu[j+n-1];
		overflow = spDivide(&qhat, &rhat, t, v[n-1]);

		/* Test Qhat */
		if (overflow)
		{   /* Qhat == b so set Qhat = b - 1 */
			qhat = MAX_DIGIT;
			rhat = uu[j+n-1];
			rhat += v[n-1];
			if (rhat < v[n-1])  /* Rhat >= b, so no re-test */
				qhatOK = 1;
		}
		/* [VERSION 2: Added extra test "qhat && "] */
		if (qhat && !qhatOK && QhatTooBig(qhat, rhat, v[n-2], uu[j+n-2]))
		{   /* If Qhat.Vn-2 > b.Rhat + Uj+n-2 
			   decrease Qhat by one, increase Rhat by Vn-1
			*/
			qhat--;
			rhat += v[n-1];
			/* Repeat this test if Rhat < b */
			if (!(rhat < v[n-1]))
				if (QhatTooBig(qhat, rhat, v[n-2], uu[j+n-2]))
					qhat--;
		}


		/* Step D4. Multiply and subtract */
		ww = &uu[j];
		overflow = mpMultSub(t[1], ww, v, qhat, (int)n);

		/* Step D5. Test remainder. Set Qj = Qhat */
		q[j] = qhat;
		if (overflow)
		{   /* Step D6. Add back if D4 was negative */
			q[j]--;
			overflow = mpAdd(ww, ww, v, (int)n);
		}

		t[0] = uu[j+n-1];   /* Uj+n on next round */

	}   /* Step D7. Loop on j */

	/* Clear high digits in uu */
	for (j = n; j < m+n; j++)
		uu[j] = 0;

	/* Step D8. Unnormalise. */

	mpShiftRight(r, r, shift, n);
	mpShiftRight(v, v, shift, n);

	return 0;
}

/***************************/
static int mpModulo(unsigned int r[], const unsigned int u[], int udigits, 
			 unsigned int v[], int vdigits)
{
	/*  Computes r = u mod v
		where r, v are multiprecision integers of length vdigits
		and u is a multiprecision integer of length udigits.
		r may overlap v.

		Note that r here is only vdigits long, 
		whereas in mpDivide it is udigits long.

		Use remainder from mpDivide function.
	*/

	int nn = max(udigits, vdigits);

	// [v2.6] increased to two times
	if (nn > (MAX_FIXED_DIGITS*2))
	{
		printf("Error!! mpModulo nn overflow!\n");
		return -1;
	}

	/* rr[nn] = u mod v */
	mpDivide(qq, rr, u, udigits, v, vdigits);

	/* Final r is only vdigits long */
	mpSetEqual(r, rr, vdigits);
	return 0;
}


static void Hex2Binary(char * input, char *output)
{
	int    i, j, idx, n, klen;
	char   *p = (char *)input;

	if (strlen(input)+3 > RSA_KBUF_HLEN)
	{
		printf("Hex2Binary overflow!!  %d > %d\n", klen+3, RSA_KBUF_HLEN);
	}
	
	klen = strlen(input)*4;
	
	memset(output, 0, RSA_KBUF_BLEN);
	output[klen] = 0;
	output[klen+1] = 0;
	
	idx = klen-1;

	for (i = 0; *p != 0; i++, p++) 
	{
		if (input[i] <= '9')
			n = input[i] - '0';
		else if (input[i] >= 'a')
			n = input[i] - 'a' + 10;
		else
			n = input[i] - 'A' + 10;
		
		for (j = 3; j >= 0; j--)
			output[idx--] = (n >> j) & 0x1;
	}
	
	if (idx != -1)
	{
		printf("Hex2Binary unexpected error!!\n");
	}
}

static void Binary2Hex(int length, char *input, char *output)
{
	int    i, idx, n, slen;
	
	memset(output, 0, RSA_KBUF_HLEN);
	
	slen = length / 4;
	
	idx  = slen - 1;
	
	for (i=0; i<length; i+=4) 
	{
		n = (input[i]) | (input[i+1]<<1) | (input[i+2]<<2) | (input[i+3]<<3);
		if (n >= 10)
			output[idx] = n - 10 + 'A';
		else
			output[idx] = n + '0'; 
		idx--;
	}
	
	if (idx != -1)
	{
		printf("Binary2Hex unecpected error! %d\n", idx);
	}
}

#define Hardware_length   (2096)

static unsigned int  C_t[(2096*2)/32];
static unsigned int  N_t[(2096*2)/32];

static char   C[RSA_KBUF_BLEN], N[RSA_KBUF_BLEN];


static void RSA_Calculate_C(int length, char *rsa_N, char *rsa_C)
{
	int        i, v, nbits;
	unsigned int   j;
	int        scale = (length+2)*2;
	size_t     word_size = (scale/32)+1;

	memset(rsa_C, 0, length/4+2);
	Hex2Binary(rsa_N, N);  

	memset(C_t, 0, sizeof(C_t));
	C_t[word_size-1] = (unsigned int)(1 << (scale-(32*(word_size-1))));

	// convert char to unsigned int
	memset(N_t, 0, sizeof(N_t));
	j = 0;
	for (i = 0; i < length; i++)
	{
		if (N[i])
		{
			j += 1 << (i%32);
		}

		if ((i % 32) == 31)
		{
			N_t[(i/32)] = j;
			j = 0;
		}
	}
	mpModulo(C_t, C_t, word_size, N_t, word_size);

	// convert unsigned int to char
	nbits = (int)mpBitLength(C_t, word_size);
	for (i = Hardware_length; i >= 0; i--) 
	{
		if (i > nbits) 
			C[i] = 0;
		else
		{
			v = mpGetBit(C_t, word_size, i);
			C[i] = v ? 1 : 0;
		}
	}
	Binary2Hex(length, C, rsa_C);
}

char    g_rsa_N[RSA_KBUF_HLEN] = "bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1";
char    g_rsa_E[RSA_KBUF_HLEN] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
char    g_rsa_D[RSA_KBUF_HLEN] = "40d60f24b61d76783d3bb1dc00b55f96a2a686f59b3750fdb15c40251c370c65cada222673811bc6b305ed7c90ffcb3abdddc8336612ff13b42a75cb7c88fb936291b523d80acce5a0842c724ed85a1393faf3d470bda8083fa84dc5f31499844f0c7c1e93fb1f734a5a29fb31a35c8a0822455f1c850a49e8629714ec6a2657efe75ec1ca6e62f9a3756c9b20b4855bdc9a3ab58c43d8af85b837a7fd15aa1149c119cfe960c05a9d4cea69c9fb6a897145674882bf57241d77c054dc4c94e8349d376296137eb421686159cb878d15d171eda8692834afc871988f203fc822c5dcee7f6c48df663ea3dc755e7dc06aebd41d05f1ca2891e2679783244d068f";
char    g_rsa_M[RSA_KBUF_HLEN] = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";
char    g_rsa_S[RSA_KBUF_HLEN] = "7e65b998a05f626b028c75dc3fbf98963dce66d0f4c3ae4237cff304d84d8836cb6bad9ac86f9d1b8a28dd70404788b869d2429f1ec0663e51b753f7451c6b4645d99126e457c1dac49551d86a8a974a3131e9b371d5c214cc9ff240c299bd0e62dbc7a9a2dad9fa5404adb00632d36332d5be6106e9e6ec81cac45cd339cc87abbe7f89430800e16e032a66210b25e926eda243d9f09955496ddbc77ef74f17fee41c4435e78b46965b713d72ce8a31af641538add387fedfd88bb22a42eb3bda40f72ecad941dbffdd47b3e77737da741553a45b630d070bcc5205804bf80ee2d51612875dbc4796960052f1687e0074007e6a33ab8b2085c033f9892b6f74";
char    g_rsa_C[RSA_KBUF_HLEN]; // = "AABFDCCC90C70BDF6BAF188066B42B25D0D1E995428E6209B0871DE6913F602D08251C8C87218CEDD462FEE6456DC6B2BAB044F11E4D0EF30070729196D2FF0B7A9F16B07D3FE2FA8B39EAAE0D546F058074C9C55DD85D8156B131CA014F4BCDE6A8E21D11491ECC2382DC8BB373E2419427A3096637C5C09338DB5DA939A16FF88307F06CEC7BB2EBBAF7E6AA682FA7F5D188D50BE3DC43138B60EE584D007AC17FC3BA98D9FE65F91D20D0EB5A9EE9B895D066A9D1C0369E4C93C4F39328B4EB2437574AB3DA90B334AD864A4FA622D01E17174A7B1222775925AB3D0667CCF5D9FC084C9C6DD59B41DA3C36E9D10E8EF4C848C63CE48E76AF9130D1748B18";
char    g_rsa_tmp[RSA_KBUF_HLEN];

int Nuvoton_Init_RSA(void)
{
	fd_rsa = open(NVT_RSA, O_RDWR);
	if (fd_rsa < 0) 
	{
		printf("open %s error\n", NVT_RSA);
		return fd_rsa;
	}
	return 0;
}

void Nuvoton_Deinit_RSA(void)
{
   	close(fd_rsa);
}

int RSA_raw_demo(void)
{
	int  i, ret;

	printf("\n+-------------------------------------------------------------+\n");
	printf("|  [RAW] RSA sign                                               |\n");
	printf("+---------------------------------------------------------------+\n");
	
	ioctl(fd_rsa, RSA_IOC_SET_BIT_LEN, 2048);
	ioctl(fd_rsa, RSA_IOC_SET_N, g_rsa_N);
	RSA_Calculate_C(2048, g_rsa_N, g_rsa_C);
	ioctl(fd_rsa, RSA_IOC_SET_C, g_rsa_C);
	ioctl(fd_rsa, RSA_IOC_SET_D, g_rsa_D);       /* set private key   */
	ioctl(fd_rsa, RSA_IOC_SET_MSG, g_rsa_M);     /* set message       */
	ioctl(fd_rsa, RSA_IOC_DO_SIGN, 0);           /* do RSA sign       */
	
	ioctl(fd_rsa, RSA_IOC_GET_SIG, g_rsa_tmp);
	printf("RSA Signature is: %s\n", g_rsa_tmp);

	ioctl(fd_rsa, RSA_IOC_SET_N, g_rsa_N);
	ioctl(fd_rsa, RSA_IOC_SET_C, g_rsa_C);
	ioctl(fd_rsa, RSA_IOC_SET_E, g_rsa_E);       /* set public key    */
	ioctl(fd_rsa, RSA_IOC_SET_SIG, g_rsa_S);     /* set message       */
	ret = ioctl(fd_rsa, RSA_IOC_DO_VERIFY, 0);   /* do RSA verify     */

	ioctl(fd_rsa, RSA_IOC_GET_MSG, g_rsa_tmp);
	printf("RSA verify result is: %s\n", g_rsa_tmp);
	
	if (ret == 0)
		printf("RSA signature verify OK.\n");
	else
		printf("RSA signature verify failed!!\n");
	return ret;
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

	/* RSA */
	if (Nuvoton_Init_RSA() != 0)
		return;
	RSA_raw_demo();
	Nuvoton_Deinit_RSA();
}



