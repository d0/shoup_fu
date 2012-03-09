#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <NTL/ZZ_pX.h>

#define threshold 3
#define num_nodes 5
#define e 65537

NTL_CLIENT

int main() {
    RSA *rsa = NULL;
    ZZ_pX poly;
    char *tmp = NULL;

    /* Generate RSA key */
    rsa = RSA_generate_key(2048, e, NULL, NULL);
    if (!rsa)
        return -1;

    /* Extract modulus and initalize NTL to use it */
    tmp = BN_bn2dec(rsa->n);
    ZZ_p::init(to_ZZ(tmp));
    free(tmp);

    /* Extract secret exponent */
    ZZ_p secret_exponent;
    tmp = BN_bn2dec(rsa->d);
    secret_exponent = to_ZZ_p(to_ZZ(tmp));

    /* Generate random polynomial of degree t+1 o that f(0) = secret exponent */
    random(poly, threshold + 1);
    SetCoeff(poly, 0, 0);
    SetCoeff(poly, 0, secret_exponent);

    RSA_print_fp(stdout, rsa, 0);
//    printf("d = %s\n", BN_bn2dec(rsa->d));
    printf("\n");
    printf("\n");
    std::cout << poly;
    printf("\n");
err:
    if (rsa)
        RSA_free(rsa);
    if (tmp)
        free(tmp);
    return 0;
}
