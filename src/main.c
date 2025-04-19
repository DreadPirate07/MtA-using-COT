#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "rand.h"
#include "ecdsa.h"
#include "bignum.h"
#include "sha2.h"
#include "hasher.h"

extern const ecdsa_curve secp256k1;
static void correlated_ot(const ecdsa_curve* curve,const bignum256* a,int y_i,bignum256* m_c,bignum256* u_i);
static void mta_additive(const ecdsa_curve* curve,bignum256* a,bignum256* b,bignum256* C, bignum256* D);
static void print_bn_hex(const bignum256 *x);
static bignum256* gen_bn(const ecdsa_curve* curve);
static void random_scalar(bignum256 *k,const bignum256 *order);

// there was no method for scalar multiplication of two bignum numbers
// simply works by adding a , b times 
static void scalar_mul_mod(bignum256 *res, const bignum256 *a, const bignum256 *b, const bignum256 *order)
{

    bn_zero(res);
    bignum256 tmp; 
    bn_copy(a, &tmp);

    for (int i = 0; i < 256; i++) {
        if (bn_testbit((bignum256*)b, i)) {
            bn_addmod(res, &tmp, order);
        }
        bn_lshift(&tmp);
        bn_mod(&tmp, order);
    }
}

// XOR helper
static void xor_bytes(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

// negate EC point: R = -P  
static void point_neg(const ecdsa_curve *curve, const curve_point *p, curve_point *r) {
    r->x = p->x;

    // R.y = prime - P.y
    bn_subtract(&curve->prime, &p->y, &r->y);
    bn_mod(&r->y, &curve->prime);
}

// print bignum as hexadecimal characters
static void print_bn_hex(const bignum256 *x) {
    uint8_t buf[32];
    bn_write_be(x,buf);
    for(int i=0;i<sizeof(buf);i++) {
        printf("%02x",buf[i]);
    }
}

// generate a random bignum256 scalar
static bignum256* gen_bn(const ecdsa_curve* curve) {
    bignum256* bn = malloc(sizeof(bignum256));
    random_scalar(bn,&curve->order);
    return bn;
} 

// generates a random scalar
static void random_scalar(bignum256 *k,const bignum256 *order) {
    uint8_t buf[32];
    int  fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) abort();
    do {
        if (read(fd, buf, 32) != 32) abort();
        bn_read_be(buf, k);
    } while (bn_is_zero(k) || !bn_is_less(k,order));
    close(fd);
}


// get ith bit
static int bn_get_bit(const bignum256 *a, int i) {
    return bn_testbit((bignum256*)a, i);
}

// COT operations
static void correlated_ot(const ecdsa_curve* curve,const bignum256* x,int y_i,bignum256* mci,bignum256* U_i)
{
    const bignum256 *order = &curve->order;
    uint8_t buf0[32], buf1[32], key0[32], key1[32];
    uint8_t e0[32], e1[32], mc_bytes[32];

    random_scalar(U_i, order);

    // m0 = U_i, m1 = U_i + x mod order
    bignum256 m0 = *U_i;
    bignum256 m1;
    bn_copy(U_i,&m1);
    bn_add(&m1, x);
    bn_mod(&m1, order);

    // diffie-Hellman exchange (simulated)
    bignum256 a_i, b_i;
    random_scalar(&a_i, order);
    random_scalar(&b_i, order);
    curve_point A, B0, B;
    scalar_multiply(curve, &a_i, &A);
    scalar_multiply(curve, &b_i, &B0);
    B = B0;
    if (y_i) point_add(curve, &A, &B);

    // compute EC secrets: k0p = a_i * B, k1p = a_i * (B - A)
    curve_point k0p, k1p, B_min_A, A_neg;
    point_neg(curve, &A, &A_neg);
    point_multiply(curve, &a_i, &B, &k0p);
    B_min_A = B;
    point_add(curve, &A_neg, &B_min_A);
    point_multiply(curve, &a_i, &B_min_A, &k1p);

    // derive symmetric keys via SHA-256
    bn_write_be(&k0p.x, buf0);
    sha256_Raw(buf0, 32, key0);
    bn_write_be(&k1p.x, buf1);
    sha256_Raw(buf1, 32, key1);

    // encrypt m0, m1 to e0, e1
    uint8_t m0b[32], m1b[32];
    bn_write_be(&m0, m0b);
    bn_write_be(&m1, m1b);
    
    // e0 = m0 ⊕ key0  
    // e1 = m1 ⊕ key1 
    xor_bytes(m0b, key0, e0, 32);
    xor_bytes(m1b, key1, e1, 32);

    // decryption key kc = b_i * A
    curve_point Kc;
    point_multiply(curve, &b_i, &A, &Kc);
    uint8_t bufc[32], keyc[32];
    bn_write_be(&Kc.x, bufc);
    sha256_Raw(bufc, 32, keyc);

    // decrypts chosen ciphertext
    // if y = 0:m_c = e₀ ⊕ Keyc
    // if y = 1:m_c = e₁ ⊕ Keyc  
    const uint8_t *chosen = y_i ? e1 : e0;
    xor_bytes(chosen, keyc, mc_bytes, 32);
    bn_read_be(mc_bytes, mci);
}


static void mta_additive(const ecdsa_curve* curve,bignum256* a,bignum256* b,bignum256* C, bignum256* D)
{
    const bignum256 *order = &curve->order;
    bignum256 U_sum, V_sum;
    bn_zero(&U_sum);
    bn_zero(&V_sum);

    // for k-256 operations
    for (int i = 0; i < 256; i++) {
        int y_i = bn_get_bit(b, i);
        bignum256 U_i, mci, tmp;

        correlated_ot(curve, a, y_i,&mci,&U_i);

        // tmp = U_i * 2^i (mod order)
        tmp = U_i;
        for (int j = 0; j < i; j++) {
            bn_lshift(&tmp);
            bn_mod(&tmp, order);
        }
        bn_addmod(&U_sum, &tmp, order);

        // tmp = mci * 2^i (mod order)
        tmp = mci;
        for (int j = 0; j < i; j++) {
            bn_lshift(&tmp);
            bn_mod(&tmp, order);
        }
        bn_addmod(&V_sum, &tmp, order);
    }

    bn_subtract(&curve->order, &U_sum, C);
    bn_mod(C, &curve->order);
    *D = V_sum;
}

int main() {
    // secp256k1 parameters
    const ecdsa_curve* curve = &secp256k1;
    
    // generate a & b (random)
    bignum256 a,b;
    random_scalar(&a,&curve->order);
    random_scalar(&b,&curve->order);
    
    printf("a = "); print_bn_hex(&a);
    printf("\n");
    printf("b = "); print_bn_hex(&b);
    printf("\n");

    // compute additive shares
    bignum256 C, D;
    mta_additive(curve, &a, &b, &C, &D);

    printf("C = "); print_bn_hex(&C);
    printf("\n");
    printf("D = "); print_bn_hex(&D);
    printf("\n");

    // check: (C + D) mod order == (a*b) mod order
    bignum256 sum, prod;
    prod = a;
    sum = C;
    bn_add(&sum, &D);
    bn_mod(&sum, &curve->order);
    
    // call scalar multiply function, custom made.
    scalar_mul_mod(&prod,&a,&b,&curve->order);
    bn_mod(&prod, &curve->order);
    
    printf("a.b= "); print_bn_hex(&prod);
    printf("\n");
    printf("C+D= "); print_bn_hex(&sum);
    printf("\n");

    return 0;
}
