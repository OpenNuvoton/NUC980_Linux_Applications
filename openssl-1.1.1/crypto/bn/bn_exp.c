/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/constant_time_locl.h"
#include "bn_lcl.h"

#include <stdlib.h>
#ifdef _WIN32
# include <malloc.h>
# ifndef alloca
#  define alloca _alloca
# endif
#elif defined(__GNUC__)
# ifndef alloca
#  define alloca(s) __builtin_alloca((s))
# endif
#elif defined(__sun)
# include <alloca.h>
#endif

#include "rsaz_exp.h"

#undef SPARC_T4_MONT
#if defined(OPENSSL_BN_ASM_MONT) && (defined(__sparc__) || defined(__sparc))
# include "sparc_arch.h"
extern unsigned int OPENSSL_sparcv9cap_P[];
# define SPARC_T4_MONT
#endif

/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE      32

/* this one works - simple but works */
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int i, bits, ret = 0;
    BIGNUM *v, *rr;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_EXP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    BN_CTX_start(ctx);
    rr = ((r == a) || (r == p)) ? BN_CTX_get(ctx) : r;
    v = BN_CTX_get(ctx);
    if (rr == NULL || v == NULL)
        goto err;

    if (BN_copy(v, a) == NULL)
        goto err;
    bits = BN_num_bits(p);

    if (BN_is_odd(p)) {
        if (BN_copy(rr, a) == NULL)
            goto err;
    } else {
        if (!BN_one(rr))
            goto err;
    }

    for (i = 1; i < bits; i++) {
        if (!BN_sqr(v, v, ctx))
            goto err;
        if (BN_is_bit_set(p, i)) {
            if (!BN_mul(rr, rr, v, ctx))
                goto err;
        }
    }
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
               BN_CTX *ctx)
{
    int ret;
    
    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    /*-
     * For even modulus  m = 2^k*m_odd, it might make sense to compute
     * a^p mod m_odd  and  a^p mod 2^k  separately (with Montgomery
     * exponentiation for the odd part), using appropriate exponent
     * reductions, and combine the results using the CRT.
     *
     * For now, we use Montgomery only if the modulus is odd; otherwise,
     * exponentiation using the reciprocal-based quick remaindering
     * algorithm is used.
     *
     * (Timing obtained with expspeed.c [computations  a^p mod m
     * where  a, p, m  are of the same length: 256, 512, 1024, 2048,
     * 4096, 8192 bits], compared to the running time of the
     * standard algorithm:
     *
     *   BN_mod_exp_mont   33 .. 40 %  [AMD K6-2, Linux, debug configuration]
     *                     55 .. 77 %  [UltraSparc processor, but
     *                                  debug-solaris-sparcv8-gcc conf.]
     *
     *   BN_mod_exp_recp   50 .. 70 %  [AMD K6-2, Linux, debug configuration]
     *                     62 .. 118 % [UltraSparc, debug-solaris-sparcv8-gcc]
     *
     * On the Sparc, BN_mod_exp_recp was faster than BN_mod_exp_mont
     * at 2048 and more bits, but at 512 and 1024 bits, it was
     * slower even than the standard algorithm!
     *
     * "Real" timings [linux-elf, solaris-sparcv9-gcc configurations]
     * should be obtained when the new Montgomery reduction code
     * has been integrated into OpenSSL.)
     */

#define MONT_MUL_MOD
#define MONT_EXP_WORD
#define RECP_MUL_MOD

#ifdef MONT_MUL_MOD
    if (BN_is_odd(m)) {
# ifdef MONT_EXP_WORD
        if (a->top == 1 && !a->neg
            && (BN_get_flags(p, BN_FLG_CONSTTIME) == 0)
            && (BN_get_flags(a, BN_FLG_CONSTTIME) == 0)
            && (BN_get_flags(m, BN_FLG_CONSTTIME) == 0)) {
            BN_ULONG A = a->d[0];
            ret = BN_mod_exp_mont_word(r, A, p, m, ctx, NULL);
        } else
# endif
            ret = BN_mod_exp_mont(r, a, p, m, ctx, NULL);
    } else
#endif
#ifdef RECP_MUL_MOD
    {
        ret = BN_mod_exp_recp(r, a, p, m, ctx);
    }
#else
    {
        ret = BN_mod_exp_simple(r, a, p, m, ctx);
    }
#endif

    bn_check_top(r);
    return ret;
}

int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_RECP_CTX recp;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_RECP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    aa = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    BN_RECP_CTX_init(&recp);
    if (m->neg) {
        /* ignore sign of 'm' */
        if (!BN_copy(aa, m))
            goto err;
        aa->neg = 0;
        if (BN_RECP_CTX_set(&recp, aa, ctx) <= 0)
            goto err;
    } else {
        if (BN_RECP_CTX_set(&recp, m, ctx) <= 0)
            goto err;
    }

    if (!BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!BN_mod_mul_reciprocal(aa, val[0], val[0], &recp, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul_reciprocal(val[i], val[i - 1], aa, &recp, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!BN_mod_mul_reciprocal(r, r, val[wvalue >> 1], &recp, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_RECP_CTX_free(&recp);
    bn_check_top(r);
    return ret;
}


#ifdef USE_NUVOTON_RSA

int  fd_rsa = -1;
sem_t  rsa_semaphore;

int Nuvoton_Init_RSA(void)
{
	if (fd_rsa >= 0)
		return 0;
		
	fd_rsa = open(NVT_RSA, O_RDWR);
	if (fd_rsa < 0) 
	{
		printf("open %s error\n", NVT_RSA);
		return fd_rsa;
	}
    sem_init(&rsa_semaphore, 0, 1);
	return 0;
}

void Nuvoton_Deinit_RSA(void)
{
    if (fd_rsa >= 0)
    {
    	close(fd_rsa);
    	fd_rsa = -1;
    	sem_destroy(&rsa_semaphore);
	}
}

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

	klen = strlen(input)*4;

	if (strlen(input)+3 > RSA_KBUF_HLEN)
	{
		printf("Hex2Binary overflow!!  %d > %d\n", klen+3, RSA_KBUF_HLEN);
	}
	
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

//static char   g_rsa_N[RSA_KBUF_HLEN] = { 0 };

//debug
static char   g_rsa_N[RSA_KBUF_HLEN*8] = { 0 };

#endif


int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d, *r;
    const BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

#ifdef USE_NUVOTON_RSA
	if (fd_rsa < 0)
		Nuvoton_Init_RSA();

	if ((fd_rsa >= 0) && (a->dmax <= 64) && (p->dmax <= 64) && (m->dmax <= 64))
	{
		char   *tmpS;
		char   strbuf[RSA_KBUF_HLEN];
		int    rsa_len=2048;
		
		sem_wait(&rsa_semaphore);
		
		ioctl(fd_rsa, RSA_IOC_SET_BIT_LEN, rsa_len);
    	
		tmpS = BN_bn2hex(m);
		//printf("m[N][%d]: %s, %d\n", m->dmax, tmpS, strlen(tmpS));
		
		if (strcmp(tmpS, g_rsa_N) != 0)
		{
			strcpy(g_rsa_N, tmpS);
			ioctl(fd_rsa, RSA_IOC_SET_N, g_rsa_N);
		
			RSA_Calculate_C(rsa_len, g_rsa_N, strbuf);
			ioctl(fd_rsa, RSA_IOC_SET_C, strbuf);
		}
		OPENSSL_free(tmpS);
		
		tmpS = BN_bn2hex(p);
		//printf("p[E][%d]: %s\n", p->dmax, tmpS);
		ioctl(fd_rsa, RSA_IOC_SET_D, tmpS);
		OPENSSL_free(tmpS);
		
		tmpS = BN_bn2hex(a);
		//printf("a[M][%d]: %s\n", a->dmax, tmpS);
		ioctl(fd_rsa, RSA_IOC_SET_MSG, tmpS);
		OPENSSL_free(tmpS);
		
		ioctl(fd_rsa, RSA_IOC_DO_SIGN, 0);           /* do RSA sign       */
    	
		memset(strbuf, 0, sizeof(strbuf));
		ioctl(fd_rsa, RSA_IOC_GET_SIG, strbuf);
		//printf("H/W: %s\n", strbuf);
		
		sem_post(&rsa_semaphore);
		
		BN_hex2bn(&rr, strbuf);
		return 1;
	}
#endif

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        return BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont);
    }

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }
    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    /*
     * If this is not done, things will break in the montgomery part
     */

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_nnmod(val[0], a, m, ctx))
            goto err;
        aa = val[0];
    } else
        aa = a;
    if (!bn_to_mont_fixed_top(val[0], aa, mont, ctx))
        goto err;               /* 1 */

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!bn_mul_mont_fixed_top(d, val[0], val[0], mont, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !bn_mul_mont_fixed_top(val[i], val[i - 1], d, mont, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

#if 1                           /* by Shay Gueron's suggestion */
    j = m->top;                 /* borrow j */
    if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        if (bn_wexpand(r, j) == NULL)
            goto err;
        /* 2^(top*BN_BITS2) - m */
        r->d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < j; i++)
            r->d[i] = (~m->d[i]) & BN_MASK2;
        r->top = j;
        r->flags |= BN_FLG_FIXED_TOP;
    } else
#endif
    if (!bn_to_mont_fixed_top(r, BN_value_one(), mont, ctx))
        goto err;
    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                if (!bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!bn_mul_mont_fixed_top(r, r, val[wvalue >> 1], mont, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    /*
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        j = mont->N.top;        /* borrow j */
        val[0]->d[0] = 1;       /* borrow val[0] */
        for (i = 1; i < j; i++)
            val[0]->d[i] = 0;
        val[0]->top = j;
        if (!BN_mod_mul_montgomery(rr, r, val[0], mont, ctx))
            goto err;
    } else
#endif
    if (!BN_from_montgomery(rr, r, mont, ctx))
        goto err;
    ret = 1;
 err:
    if (in_mont == NULL)
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);

    return ret;
}

static BN_ULONG bn_get_bits(const BIGNUM *a, int bitpos)
{
    BN_ULONG ret = 0;
    int wordpos;

    wordpos = bitpos / BN_BITS2;
    bitpos %= BN_BITS2;
    if (wordpos >= 0 && wordpos < a->top) {
        ret = a->d[wordpos] & BN_MASK2;
        if (bitpos) {
            ret >>= bitpos;
            if (++wordpos < a->top)
                ret |= a->d[wordpos] << (BN_BITS2 - bitpos);
        }
    }

    return ret & BN_MASK2;
}

/*
 * BN_mod_exp_mont_consttime() stores the precomputed powers in a specific
 * layout so that accessing any of these table values shows the same access
 * pattern as far as cache lines are concerned.  The following functions are
 * used to transfer a BIGNUM from/to that table.
 */

static int MOD_EXP_CTIME_COPY_TO_PREBUF(const BIGNUM *b, int top,
                                        unsigned char *buf, int idx,
                                        int window)
{
    int i, j;
    int width = 1 << window;
    BN_ULONG *table = (BN_ULONG *)buf;

    if (top > b->top)
        top = b->top;           /* this works because 'buf' is explicitly
                                 * zeroed */
    for (i = 0, j = idx; i < top; i++, j += width) {
        table[j] = b->d[i];
    }

    return 1;
}

static int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b, int top,
                                          unsigned char *buf, int idx,
                                          int window)
{
    int i, j;
    int width = 1 << window;
    /*
     * We declare table 'volatile' in order to discourage compiler
     * from reordering loads from the table. Concern is that if
     * reordered in specific manner loads might give away the
     * information we are trying to conceal. Some would argue that
     * compiler can reorder them anyway, but it can as well be
     * argued that doing so would be violation of standard...
     */
    volatile BN_ULONG *table = (volatile BN_ULONG *)buf;

    if (bn_wexpand(b, top) == NULL)
        return 0;

    if (window <= 3) {
        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < width; j++) {
                acc |= table[j] &
                       ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    } else {
        int xstride = 1 << (window - 2);
        BN_ULONG y0, y1, y2, y3;

        i = idx >> (window - 2);        /* equivalent of idx / xstride */
        idx &= xstride - 1;             /* equivalent of idx % xstride */

        y0 = (BN_ULONG)0 - (constant_time_eq_int(i,0)&1);
        y1 = (BN_ULONG)0 - (constant_time_eq_int(i,1)&1);
        y2 = (BN_ULONG)0 - (constant_time_eq_int(i,2)&1);
        y3 = (BN_ULONG)0 - (constant_time_eq_int(i,3)&1);

        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < xstride; j++) {
                acc |= ( (table[j + 0 * xstride] & y0) |
                         (table[j + 1 * xstride] & y1) |
                         (table[j + 2 * xstride] & y2) |
                         (table[j + 3 * xstride] & y3) )
                       & ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    }

    b->top = top;
    b->flags |= BN_FLG_FIXED_TOP;
    return 1;
}

/*
 * Given a pointer value, compute the next address that is a cache line
 * multiple.
 */
#define MOD_EXP_CTIME_ALIGN(x_) \
        ((unsigned char*)(x_) + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (((size_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

/*
 * This variant of BN_mod_exp_mont() uses fixed windows and the special
 * precomputation memory layout to limit data-dependency to a minimum to
 * protect secret exponents (cf. the hyper-threading timing attacks pointed
 * out by Colin Percival,
 * http://www.daemonology.net/hyperthreading-considered-harmful/)
 */
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont)
{
    int i, bits, ret = 0, window, wvalue, wmask, window0;
    int top;
    BN_MONT_CTX *mont = NULL;

    int numPowers;
    unsigned char *powerbufFree = NULL;
    int powerbufLen = 0;
    unsigned char *powerbuf = NULL;
    BIGNUM tmp, am;
#if defined(SPARC_T4_MONT)
    unsigned int t4 = 0;
#endif

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT_CONSTTIME, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }

    top = m->top;

    /*
     * Use all bits stored in |p|, rather than |BN_num_bits|, so we do not leak
     * whether the top bits are zero.
     */
    bits = p->top * BN_BITS2;
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_CTX_start(ctx);

    /*
     * Allocate a montgomery context if it was not supplied by the caller. If
     * this is not done, things will break in the montgomery part.
     */
    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

#ifdef RSAZ_ENABLED
    if (!a->neg) {
        /*
         * If the size of the operands allow it, perform the optimized
         * RSAZ exponentiation. For further information see
         * crypto/bn/rsaz_exp.c and accompanying assembly modules.
         */
        if ((16 == a->top) && (16 == p->top) && (BN_num_bits(m) == 1024)
            && rsaz_avx2_eligible()) {
            if (NULL == bn_wexpand(rr, 16))
                goto err;
            RSAZ_1024_mod_exp_avx2(rr->d, a->d, p->d, m->d, mont->RR.d,
                                   mont->n0[0]);
            rr->top = 16;
            rr->neg = 0;
            bn_correct_top(rr);
            ret = 1;
            goto err;
        } else if ((8 == a->top) && (8 == p->top) && (BN_num_bits(m) == 512)) {
            if (NULL == bn_wexpand(rr, 8))
                goto err;
            RSAZ_512_mod_exp(rr->d, a->d, p->d, m->d, mont->n0[0], mont->RR.d);
            rr->top = 8;
            rr->neg = 0;
            bn_correct_top(rr);
            ret = 1;
            goto err;
        }
    }
#endif

    /* Get the window size to use with size of p. */
    window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(SPARC_T4_MONT)
    if (window >= 5 && (top & 15) == 0 && top <= 64 &&
        (OPENSSL_sparcv9cap_P[1] & (CFR_MONTMUL | CFR_MONTSQR)) ==
        (CFR_MONTMUL | CFR_MONTSQR) && (t4 = OPENSSL_sparcv9cap_P[0]))
        window = 5;
    else
#endif
#if defined(OPENSSL_BN_ASM_MONT5)
    if (window >= 5) {
        window = 5;             /* ~5% improvement for RSA2048 sign, and even
                                 * for RSA4096 */
        /* reserve space for mont->N.d[] copy */
        powerbufLen += top * sizeof(mont->N.d[0]);
    }
#endif
    (void)0;

    /*
     * Allocate a buffer large enough to hold all of the pre-computed powers
     * of am, am itself and tmp.
     */
    numPowers = 1 << window;
    powerbufLen += sizeof(m->d[0]) * (top * numPowers +
                                      ((2 * top) >
                                       numPowers ? (2 * top) : numPowers));
#ifdef alloca
    if (powerbufLen < 3072)
        powerbufFree =
            alloca(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH);
    else
#endif
        if ((powerbufFree =
             OPENSSL_malloc(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH))
            == NULL)
        goto err;

    powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
    memset(powerbuf, 0, powerbufLen);

#ifdef alloca
    if (powerbufLen < 3072)
        powerbufFree = NULL;
#endif

    /* lay down tmp and am right after powers table */
    tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
    am.d = tmp.d + top;
    tmp.top = am.top = 0;
    tmp.dmax = am.dmax = top;
    tmp.neg = am.neg = 0;
    tmp.flags = am.flags = BN_FLG_STATIC_DATA;

    /* prepare a^0 in Montgomery domain */
#if 1                           /* by Shay Gueron's suggestion */
    if (m->d[top - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        /* 2^(top*BN_BITS2) - m */
        tmp.d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < top; i++)
            tmp.d[i] = (~m->d[i]) & BN_MASK2;
        tmp.top = top;
    } else
#endif
    if (!bn_to_mont_fixed_top(&tmp, BN_value_one(), mont, ctx))
        goto err;

    /* prepare a^1 in Montgomery domain */
    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_nnmod(&am, a, m, ctx))
            goto err;
        if (!bn_to_mont_fixed_top(&am, &am, mont, ctx))
            goto err;
    } else if (!bn_to_mont_fixed_top(&am, a, mont, ctx))
        goto err;

#if defined(SPARC_T4_MONT)
    if (t4) {
        typedef int (*bn_pwr5_mont_f) (BN_ULONG *tp, const BN_ULONG *np,
                                       const BN_ULONG *n0, const void *table,
                                       int power, int bits);
        int bn_pwr5_mont_t4_8(BN_ULONG *tp, const BN_ULONG *np,
                              const BN_ULONG *n0, const void *table,
                              int power, int bits);
        int bn_pwr5_mont_t4_16(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        int bn_pwr5_mont_t4_24(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        int bn_pwr5_mont_t4_32(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        static const bn_pwr5_mont_f pwr5_funcs[4] = {
            bn_pwr5_mont_t4_8, bn_pwr5_mont_t4_16,
            bn_pwr5_mont_t4_24, bn_pwr5_mont_t4_32
        };
        bn_pwr5_mont_f pwr5_worker = pwr5_funcs[top / 16 - 1];

        typedef int (*bn_mul_mont_f) (BN_ULONG *rp, const BN_ULONG *ap,
                                      const void *bp, const BN_ULONG *np,
                                      const BN_ULONG *n0);
        int bn_mul_mont_t4_8(BN_ULONG *rp, const BN_ULONG *ap, const void *bp,
                             const BN_ULONG *np, const BN_ULONG *n0);
        int bn_mul_mont_t4_16(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        int bn_mul_mont_t4_24(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        int bn_mul_mont_t4_32(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        static const bn_mul_mont_f mul_funcs[4] = {
            bn_mul_mont_t4_8, bn_mul_mont_t4_16,
            bn_mul_mont_t4_24, bn_mul_mont_t4_32
        };
        bn_mul_mont_f mul_worker = mul_funcs[top / 16 - 1];

        void bn_mul_mont_vis3(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0, int num);
        void bn_mul_mont_t4(BN_ULONG *rp, const BN_ULONG *ap,
                            const void *bp, const BN_ULONG *np,
                            const BN_ULONG *n0, int num);
        void bn_mul_mont_gather5_t4(BN_ULONG *rp, const BN_ULONG *ap,
                                    const void *table, const BN_ULONG *np,
                                    const BN_ULONG *n0, int num, int power);
        void bn_flip_n_scatter5_t4(const BN_ULONG *inp, size_t num,
                                   void *table, size_t power);
        void bn_gather5_t4(BN_ULONG *out, size_t num,
                           void *table, size_t power);
        void bn_flip_t4(BN_ULONG *dst, BN_ULONG *src, size_t num);

        BN_ULONG *np = mont->N.d, *n0 = mont->n0;
        int stride = 5 * (6 - (top / 16 - 1)); /* multiple of 5, but less
                                                * than 32 */

        /*
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 0);
        bn_flip_n_scatter5_t4(am.d, top, powerbuf, 1);
        if (!(*mul_worker) (tmp.d, am.d, am.d, np, n0) &&
            !(*mul_worker) (tmp.d, am.d, am.d, np, n0))
            bn_mul_mont_vis3(tmp.d, am.d, am.d, np, n0, top);
        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 2);

        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            if (!(*mul_worker) (tmp.d, tmp.d, am.d, np, n0) &&
                !(*mul_worker) (tmp.d, tmp.d, am.d, np, n0))
                bn_mul_mont_vis3(tmp.d, tmp.d, am.d, np, n0, top);
            bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, i);
        }

        /* switch to 64-bit domain */
        np = alloca(top * sizeof(BN_ULONG));
        top /= 2;
        bn_flip_t4(np, mont->N.d, top);

        /*
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         */
        window0 = (bits - 1) % 5 + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        bn_gather5_t4(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        while (bits > 0) {
            if (bits < stride)
                stride = bits;
            bits -= stride;
            wvalue = bn_get_bits(p, bits);

            if ((*pwr5_worker) (tmp.d, np, n0, powerbuf, wvalue, stride))
                continue;
            /* retry once and fall back */
            if ((*pwr5_worker) (tmp.d, np, n0, powerbuf, wvalue, stride))
                continue;

            bits += stride - 5;
            wvalue >>= stride - 5;
            wvalue &= 31;
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_gather5_t4(tmp.d, tmp.d, powerbuf, np, n0, top,
                                   wvalue);
        }

        bn_flip_t4(tmp.d, tmp.d, top);
        top *= 2;
        /* back to 32-bit domain */
        tmp.top = top;
        bn_correct_top(&tmp);
        OPENSSL_cleanse(np, top * sizeof(BN_ULONG));
    } else
#endif
#if defined(OPENSSL_BN_ASM_MONT5)
    if (window == 5 && top > 1) {
        /*
         * This optimization uses ideas from http://eprint.iacr.org/2011/239,
         * specifically optimization of cache-timing attack countermeasures
         * and pre-computation optimization.
         */

        /*
         * Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
         * 512-bit RSA is hardly relevant, we omit it to spare size...
         */
        void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
                                 const void *table, const BN_ULONG *np,
                                 const BN_ULONG *n0, int num, int power);
        void bn_scatter5(const BN_ULONG *inp, size_t num,
                         void *table, size_t power);
        void bn_gather5(BN_ULONG *out, size_t num, void *table, size_t power);
        void bn_power5(BN_ULONG *rp, const BN_ULONG *ap,
                       const void *table, const BN_ULONG *np,
                       const BN_ULONG *n0, int num, int power);
        int bn_get_bits5(const BN_ULONG *ap, int off);
        int bn_from_montgomery(BN_ULONG *rp, const BN_ULONG *ap,
                               const BN_ULONG *not_used, const BN_ULONG *np,
                               const BN_ULONG *n0, int num);

        BN_ULONG *n0 = mont->n0, *np;

        /*
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        /*
         * copy mont->N.d[] to improve cache locality
         */
        for (np = am.d + top, i = 0; i < top; i++)
            np[i] = mont->N.d[i];

        bn_scatter5(tmp.d, top, powerbuf, 0);
        bn_scatter5(am.d, am.top, powerbuf, 1);
        bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
        bn_scatter5(tmp.d, top, powerbuf, 2);

# if 0
        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
# else
        /* same as above, but uses squaring for 1/2 of operations */
        for (i = 4; i < 32; i *= 2) {
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
        for (i = 3; i < 8; i += 2) {
            int j;
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            for (j = 2 * i; j < 32; j *= 2) {
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_scatter5(tmp.d, top, powerbuf, j);
            }
        }
        for (; i < 16; i += 2) {
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, 2 * i);
        }
        for (; i < 32; i += 2) {
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
# endif
        /*
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         */
        window0 = (bits - 1) % 5 + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        bn_gather5(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        if (top & 7) {
            while (bits > 0) {
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top,
                                    bn_get_bits5(p->d, bits -= 5));
            }
        } else {
            while (bits > 0) {
                bn_power5(tmp.d, tmp.d, powerbuf, np, n0, top,
                          bn_get_bits5(p->d, bits -= 5));
            }
        }

        ret = bn_from_montgomery(tmp.d, tmp.d, NULL, np, n0, top);
        tmp.top = top;
        bn_correct_top(&tmp);
        if (ret) {
            if (!BN_copy(rr, &tmp))
                ret = 0;
            goto err;           /* non-zero ret means it's not error */
        }
    } else
#endif
    {
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0, window))
            goto err;
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am, top, powerbuf, 1, window))
            goto err;

        /*
         * If the window size is greater than 1, then calculate
         * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1) (even
         * powers could instead be computed as (a^(i/2))^2 to use the slight
         * performance advantage of sqr over mul).
         */
        if (window > 1) {
            if (!bn_mul_mont_fixed_top(&tmp, &am, &am, mont, ctx))
                goto err;
            if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 2,
                                              window))
                goto err;
            for (i = 3; i < numPowers; i++) {
                /* Calculate a^i = a^(i-1) * a */
                if (!bn_mul_mont_fixed_top(&tmp, &am, &tmp, mont, ctx))
                    goto err;
                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, i,
                                                  window))
                    goto err;
            }
        }

        /*
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         */
        window0 = (bits - 1) % window + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf, wvalue,
                                            window))
            goto err;

        wmask = (1 << window) - 1;
        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        while (bits > 0) {

            /* Square the result window-size times */
            for (i = 0; i < window; i++)
                if (!bn_mul_mont_fixed_top(&tmp, &tmp, &tmp, mont, ctx))
                    goto err;

            /*
             * Get a window's worth of bits from the exponent
             * This avoids calling BN_is_bit_set for each bit, which
             * is not only slower but also makes each bit vulnerable to
             * EM (and likely other) side-channel attacks like One&Done
             * (for details see "One&Done: A Single-Decryption EM-Based
             *  Attack on OpenSSL’s Constant-Time Blinded RSA" by M. Alam,
             *  H. Khan, M. Dey, N. Sinha, R. Callan, A. Zajic, and
             *  M. Prvulovic, in USENIX Security'18)
             */
            bits -= window;
            wvalue = bn_get_bits(p, bits) & wmask;
            /*
             * Fetch the appropriate pre-computed value from the pre-buf
             */
            if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf, wvalue,
                                                window))
                goto err;

            /* Multiply the result into the intermediate result */
            if (!bn_mul_mont_fixed_top(&tmp, &tmp, &am, mont, ctx))
                goto err;
        }
    }

    /*
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        am.d[0] = 1;            /* borrow am */
        for (i = 1; i < top; i++)
            am.d[i] = 0;
        if (!BN_mod_mul_montgomery(rr, &tmp, &am, mont, ctx))
            goto err;
    } else
#endif
    if (!BN_from_montgomery(rr, &tmp, mont, ctx))
        goto err;
    ret = 1;
 err:
    if (in_mont == NULL)
        BN_MONT_CTX_free(mont);
    if (powerbuf != NULL) {
        OPENSSL_cleanse(powerbuf, powerbufLen);
        OPENSSL_free(powerbufFree);
    }
    BN_CTX_end(ctx);
    return ret;
}

int BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    BN_MONT_CTX *mont = NULL;
    int b, bits, ret = 0;
    int r_is_one;
    BN_ULONG w, next_w;
    BIGNUM *r, *t;
    BIGNUM *swap_tmp;
#define BN_MOD_MUL_WORD(r, w, m) \
                (BN_mul_word(r, (w)) && \
                (/* BN_ucmp(r, (m)) < 0 ? 1 :*/  \
                        (BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
    /*
     * BN_MOD_MUL_WORD is only used with 'w' large, so the BN_ucmp test is
     * probably more overhead than always using BN_mod (which uses BN_copy if
     * a similar test returns true).
     */
    /*
     * We can use BN_mod and do not need BN_nnmod because our accumulator is
     * never negative (the result of BN_mod does not depend on the sign of
     * the modulus).
     */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
                (BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_MONT_WORD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT_WORD, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }
    if (m->top == 1)
        a %= m->d[0];           /* make sure that 'a' is reduced */

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }
    if (a == 0) {
        BN_zero(rr);
        ret = 1;
        return ret;
    }

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    if (t == NULL)
        goto err;

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    r_is_one = 1;               /* except for Montgomery factor */

    /* bits-1 >= 0 */

    /* The result is accumulated in the product r*w. */
    w = a;                      /* bit 'bits-1' of 'p' is always set */
    for (b = bits - 2; b >= 0; b--) {
        /* First, square r*w. */
        next_w = w * w;
        if ((next_w / w) != w) { /* overflow */
            if (r_is_one) {
                if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                    goto err;
                r_is_one = 0;
            } else {
                if (!BN_MOD_MUL_WORD(r, w, m))
                    goto err;
            }
            next_w = 1;
        }
        w = next_w;
        if (!r_is_one) {
            if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
                goto err;
        }

        /* Second, multiply r*w by 'a' if exponent bit is set. */
        if (BN_is_bit_set(p, b)) {
            next_w = w * a;
            if ((next_w / a) != w) { /* overflow */
                if (r_is_one) {
                    if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                        goto err;
                    r_is_one = 0;
                } else {
                    if (!BN_MOD_MUL_WORD(r, w, m))
                        goto err;
                }
                next_w = a;
            }
            w = next_w;
        }
    }

    /* Finally, set r:=r*w. */
    if (w != 1) {
        if (r_is_one) {
            if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                goto err;
            r_is_one = 0;
        } else {
            if (!BN_MOD_MUL_WORD(r, w, m))
                goto err;
        }
    }

    if (r_is_one) {             /* can happen only if a == 1 */
        if (!BN_one(rr))
            goto err;
    } else {
        if (!BN_from_montgomery(rr, r, mont, ctx))
            goto err;
    }
    ret = 1;
 err:
    if (in_mont == NULL)
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    return ret;
}

/* The old fallback, simple version :-) */
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_SIMPLE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    if (!BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!BN_mod_mul(d, val[0], val[0], m, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul(val[i], val[i - 1], d, m, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!BN_mod_mul(r, r, r, m, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!BN_mod_mul(r, r, r, m, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!BN_mod_mul(r, r, val[wvalue >> 1], m, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}
