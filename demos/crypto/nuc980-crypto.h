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
 
#ifndef _NUC980_CRYPTO_H_
#define _NUC980_CRYPTO_H_

#include <linux/types.h>
#include <linux/ioctl.h>

#define NVT_AES_KEYSZ_128			(0x00000000)			/*!<AES 128 bits key */
#define NVT_AES_KEYSZ_192			(0x00000004)			/*!<AES 192 bits key */
#define NVT_AES_KEYSZ_256			(0x00000008)			/*!<AES 256 bits key */
#define NVT_AES_ECB_MODE			(0x00000000)			/*!<AES ECB mode */
#define NVT_AES_CBC_MODE			(0x00000100)			/*!<AES CBC mode */
#define NVT_AES_CFB_MODE			(0x00000200)			/*!<AES CFB mode */
#define NVT_AES_OFB_MODE			(0x00000300)			/*!<AES OFB mode */
#define NVT_AES_CTR_MODE			(0x00000400)			/*!<AES CTR mode */
#define NVT_AES_CBCCS1_MODE			(0x00001000)			/*!<AES CBC CS1 mode */
#define NVT_AES_CBCCS2_MODE			(0x00001100)			/*!<AES CBC CS2 mode */
#define NVT_AES_CBCCS3_MODE			(0x00001200)			/*!<AES CBC CS3 mode */
#define NVT_AES_ENCRYPT				(0x00010000)			/*!<AES engine execute encryption */
#define NVT_AES_DECRYPT				(0x00000000)			/*!<AES engine execute decryption */
#define NVT_AES_OUTSWAP				(0x00400000)			/*!<AES engine output data transform */
#define NVT_AES_INSWAP				(0x00800000)			/*!<AES engine input data transform */

#define NVT_SHA1					(0x00000000)			/*!<SHA1 */
#define NVT_SHA224					(0x00000500)			/*!<SHA224 */
#define NVT_SHA256					(0x00000400)			/*!<SHA256 */
#define NVT_SHA384					(0x00000700)			/*!<SHA384 */
#define NVT_SHA512					(0x00000600)			/*!<SHA512 */
#define NVT_SHA_OUTSWAP				(0x00400000)			/*!<HMAC engine output data transform */
#define NVT_SHA_INSWAP				(0x00800000)			/*!<HMAC engine input data transform */

#define ECC_CURVE_P_192      		(0x100192)
#define ECC_CURVE_P_224      		(0x100224)
#define ECC_CURVE_P_256      		(0x100256)
#define ECC_CURVE_P_384      		(0x100384)
#define ECC_CURVE_P_521      		(0x100521)
#define ECC_CURVE_K_163      		(0x200163)
#define ECC_CURVE_K_233      		(0x200233)
#define ECC_CURVE_K_283      		(0x200283)
#define ECC_CURVE_K_409      		(0x200409)
#define ECC_CURVE_K_571      		(0x200571)
#define ECC_CURVE_B_163      		(0x300163)
#define ECC_CURVE_B_233      		(0x300233)
#define ECC_CURVE_B_283      		(0x300283)
#define ECC_CURVE_B_409      		(0x300409)
#define ECC_CURVE_B_571      		(0x300571)
#define ECC_CURVE_KO_192     		(0x400192)
#define ECC_CURVE_KO_224     		(0x400224)
#define ECC_CURVE_KO_256     		(0x400256)
#define ECC_CURVE_BP_256     		(0x500256)
#define ECC_CURVE_BP_384     		(0x500384)
#define ECC_CURVE_BP_512     		(0x500512)
#define ECC_CURVE_25519      		(0x025519)


#define CRYPTO_IOC_MAGIC		'C'

#define AES_IOC_SET_MODE		_IOW(CRYPTO_IOC_MAGIC,  1, unsigned long)
#define AES_IOC_SET_LEN			_IOW(CRYPTO_IOC_MAGIC,  2, unsigned long)
#define AES_IOC_GET_BUFSIZE     _IOW(CRYPTO_IOC_MAGIC,  3, unsigned long *)
#define AES_IOC_SET_IV			_IOW(CRYPTO_IOC_MAGIC,  5, unsigned long *)
#define AES_IOC_SET_KEY			_IOW(CRYPTO_IOC_MAGIC,  6, unsigned long *)
#define AES_IOC_START			_IOW(CRYPTO_IOC_MAGIC,  8, unsigned long)
#define AES_IOC_C_START			_IOW(CRYPTO_IOC_MAGIC,  9, unsigned long)
#define AES_IOC_UPDATE_IV		_IOW(CRYPTO_IOC_MAGIC, 11, unsigned long *)

#define SHA_IOC_INIT	  		_IOW(CRYPTO_IOC_MAGIC, 21, unsigned long)
#define SHA_IOC_FINISH			_IOW(CRYPTO_IOC_MAGIC, 25, unsigned long)

#define ECC_IOC_SEL_CURVE	  	_IOW(CRYPTO_IOC_MAGIC, 51, unsigned long)
#define ECC_IOC_SET_PRI_KEY     _IOW(CRYPTO_IOC_MAGIC, 52, unsigned char *)
#define ECC_IOC_SET_PUB_K1      _IOW(CRYPTO_IOC_MAGIC, 53, unsigned char *)
#define ECC_IOC_SET_PUB_K2      _IOW(CRYPTO_IOC_MAGIC, 54, unsigned char *)
#define ECC_IOC_SET_SCALAR_K    _IOW(CRYPTO_IOC_MAGIC, 55, unsigned char *)
#define ECC_IOC_SET_MSG         _IOW(CRYPTO_IOC_MAGIC, 56, unsigned char *)
#define ECC_IOC_SET_SIG_R       _IOW(CRYPTO_IOC_MAGIC, 57, unsigned char *)
#define ECC_IOC_SET_SIG_S       _IOW(CRYPTO_IOC_MAGIC, 58, unsigned char *)
#define ECC_IOC_GET_PUB_K1      _IOW(CRYPTO_IOC_MAGIC, 61, unsigned char *)
#define ECC_IOC_GET_PUB_K2      _IOW(CRYPTO_IOC_MAGIC, 62, unsigned char *)
#define ECC_IOC_GET_SIG_R       _IOW(CRYPTO_IOC_MAGIC, 63, unsigned char *)
#define ECC_IOC_GET_SIG_S       _IOW(CRYPTO_IOC_MAGIC, 64, unsigned char *)
#define ECC_IOC_GEN_PUB_KEY     _IOW(CRYPTO_IOC_MAGIC, 71, unsigned long)
#define ECC_IOC_ECDSA_SIGN      _IOW(CRYPTO_IOC_MAGIC, 72, unsigned long)
#define ECC_IOC_ECDSA_VERIFY    _IOW(CRYPTO_IOC_MAGIC, 73, unsigned long)
#define ECC_IOC_POINT_MUL       _IOW(CRYPTO_IOC_MAGIC, 81, unsigned long)

#define RSA_IOC_SET_BIT_LEN     _IOW(CRYPTO_IOC_MAGIC, 90, unsigned long)
#define RSA_IOC_SET_N           _IOW(CRYPTO_IOC_MAGIC, 91, unsigned char *)
#define RSA_IOC_SET_D           _IOW(CRYPTO_IOC_MAGIC, 92, unsigned char *)
#define RSA_IOC_SET_E           _IOW(CRYPTO_IOC_MAGIC, 93, unsigned char *)
#define RSA_IOC_SET_C           _IOW(CRYPTO_IOC_MAGIC, 94, unsigned char *)
#define RSA_IOC_SET_MSG         _IOW(CRYPTO_IOC_MAGIC, 95, unsigned char *)
#define RSA_IOC_GET_MSG         _IOW(CRYPTO_IOC_MAGIC, 96, unsigned char *)
#define RSA_IOC_GET_SIG         _IOW(CRYPTO_IOC_MAGIC, 97, unsigned char *)
#define RSA_IOC_SET_SIG         _IOW(CRYPTO_IOC_MAGIC, 98, unsigned char *)
#define RSA_IOC_DO_SIGN         _IOW(CRYPTO_IOC_MAGIC, 101, unsigned long)
#define RSA_IOC_DO_VERIFY       _IOW(CRYPTO_IOC_MAGIC, 102, unsigned long)

#endif

