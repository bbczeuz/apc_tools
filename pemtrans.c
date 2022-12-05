/*
 * <http://toroid.org/ams/pemtrans>
 *
 * Converts an OpenSSL PEM private key and signed certificate into a
 * cryptlib PKCS #15 key file.
 *
 * Copyright 2004 Abhijit Menon-Sen <ams@toroid.org>
 * Use, modification, and distribution of pemtrans is allowed without
 * any limitations. There is no warranty, express or implied.
 */


#include <cryptlib/cryptlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


void check( int n, CRYPT_HANDLE c, char *s )
{
    int status;
    int locus = 0;
    int type = 0;
    int length = 0;

    if ( n == CRYPT_OK )
        return;

    cryptGetAttribute( c, CRYPT_ATTRIBUTE_ERRORLOCUS, &locus );
    cryptGetAttribute( c, CRYPT_ATTRIBUTE_ERRORTYPE, &type );

    fprintf( stderr, "%s failed.\n", s );
    fprintf( stderr, "\tError code: %d\n", n );
    if ( locus != 0 )
        fprintf( stderr, "\tError locus: %d\n", locus );
    if ( type != 0 )
        fprintf( stderr, "\tError type: %d\n", type );

    status = cryptGetAttributeString( c, CRYPT_ATTRIBUTE_ERRORMESSAGE,
                                      0, &length );
    if ( cryptStatusOK( status ) ) {
        char * err = malloc( length );
        if ( !err )
            exit( -1 );
        status = cryptGetAttributeString( c, CRYPT_ATTRIBUTE_ERRORMESSAGE,
                                          err, &length );
        if ( cryptStatusOK( status ) )
            fprintf( stderr, "\tError message: %s\n", err );
    }

    exit( -1 );
}


int main( int argc, char *argv[] )
{
    int n;
    FILE *f;
    char *buf[8];
    char *outFile;
    char *keyFile;
    char *certFile;
    char *certData;
    char *label;
    char *secret;
    struct stat st;
    int usage;

    RSA *key;
    EVP_PKEY *evp;
    CRYPT_KEYSET keyset;
    CRYPT_CONTEXT pKey;
    CRYPT_PKCINFO_RSA rsa;
    CRYPT_CERTIFICATE cert;
    CRYPT_KEYOPT_TYPE opt;

    if ( argc != 6 ) {
        fprintf( stderr,
                 "Syntax: %s <key> <cert> <out> <label> <secret>\n",
                 argv[0] );
        exit( -1 );
    }

    keyFile = argv[1];
    certFile = argv[2];
    outFile = argv[3];
    label = argv[4];
    secret = argv[5];

    if ( ( f = fopen( keyFile, "r" ) ) == NULL ||
         ( evp = PEM_read_PrivateKey( f, NULL, NULL, NULL ) ) == NULL ||
         ( key = EVP_PKEY_get1_RSA( evp ) ) == NULL )
    {
        fprintf( stderr, "Couldn't load private key from '%s'\n", keyFile );
        if ( f ) {
            ERR_print_errors_fp( stderr );
            fclose( f );
        }
        if ( evp )
            EVP_PKEY_free( evp );
        exit( -1 );
    }

    if ( ( f = fopen( certFile, "r" ) ) == NULL ||
         fstat( fileno( f ), &st ) < 0 ||
         ( certData = malloc( st.st_size ) ) == NULL ||
         fread( certData, 1, st.st_size, f ) < st.st_size )
    {
        fprintf( stderr, "Couldn't load certificate from '%s'\n", certFile );
        if ( f )
            fclose( f );
        free( certData );
        exit( -1 );
    }

    /* Should we create a keyset, or append to an existing one? */
    opt = CRYPT_KEYOPT_CREATE;
    f = fopen( outFile, "r" );
    if ( f != NULL ) {
        opt = CRYPT_KEYOPT_NONE;
        fclose( f );
    }

    cryptInit();

    cryptInitComponents( &rsa, CRYPT_KEYTYPE_PRIVATE );
    if ( ( buf[0] = malloc( BN_num_bytes( RSA_get0_n(key) ) ) ) != NULL &&
         ( buf[1] = malloc( BN_num_bytes( RSA_get0_e(key) ) ) ) != NULL &&
         ( buf[2] = malloc( BN_num_bytes( RSA_get0_d(key) ) ) ) != NULL &&
         ( buf[3] = malloc( BN_num_bytes( RSA_get0_p(key) ) ) ) != NULL &&
         ( buf[4] = malloc( BN_num_bytes( RSA_get0_q(key)) ) ) != NULL &&
         ( buf[5] = malloc( BN_num_bytes( RSA_get0_iqmp(key)) ) ) != NULL &&
         ( buf[6] = malloc( BN_num_bytes( RSA_get0_dmp1(key )) ) ) != NULL &&
         ( buf[7] = malloc( BN_num_bytes( RSA_get0_dmq1(key )) ) ) != NULL )
    {
        int i;

        BN_bn2bin( RSA_get0_n(key), buf[0] );
        BN_bn2bin( RSA_get0_e(key), buf[1] );
        BN_bn2bin( RSA_get0_d(key), buf[2] );
        BN_bn2bin( RSA_get0_p(key), buf[3] );
        BN_bn2bin( RSA_get0_q(key), buf[4] );
        BN_bn2bin( RSA_get0_iqmp(key), buf[5] );
        BN_bn2bin( RSA_get0_dmp1(key), buf[6] );
        BN_bn2bin( RSA_get0_dmq1(key), buf[7] );

        cryptSetComponent( (&rsa)->n, buf[0], BN_num_bits( RSA_get0_n(key) ) );
        cryptSetComponent( (&rsa)->e, buf[1], BN_num_bits( RSA_get0_e(key) ) );
        cryptSetComponent( (&rsa)->d, buf[2], BN_num_bits( RSA_get0_d(key) ) );
        cryptSetComponent( (&rsa)->p, buf[3], BN_num_bits( RSA_get0_p(key) ) );
        cryptSetComponent( (&rsa)->q, buf[4], BN_num_bits( RSA_get0_q(key) ) );
        cryptSetComponent( (&rsa)->u, buf[5], BN_num_bits( RSA_get0_iqmp(key) ) );
        cryptSetComponent( (&rsa)->e1, buf[6], BN_num_bits(RSA_get0_dmp1(key) ) );
        cryptSetComponent( (&rsa)->e2, buf[7], BN_num_bits(RSA_get0_dmq1(key) ) );

        i = 0;
        while ( i < 8 )
            free( buf[i++] );
    }
    else {
        fprintf( stderr, "Couldn't initialise PKCINFO_RSA data.\n" );
        exit( -1 );
    }

    n = cryptCreateContext( &pKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
    check( n, pKey, "cryptCreateContext" );

    n = cryptSetAttributeString( pKey, CRYPT_CTXINFO_LABEL,
                                 label, strlen( label ) );
    check( n, pKey, "cryptSetAttributeString(LABEL)" );

    n = cryptSetAttributeString( pKey, CRYPT_CTXINFO_KEY_COMPONENTS,
                                 &rsa, sizeof( CRYPT_PKCINFO_RSA ) );
    check( n, pKey, "cryptSetAttributeString(KEY_COMPONENTS)" );

    n = cryptImportCert( certData, st.st_size, CRYPT_UNUSED, &cert );
    check( n, cert, "cryptImportCert" );

    n = cryptGetAttribute( cert, CRYPT_CERTINFO_KEYUSAGE, &usage );
    if ( n != CRYPT_OK ) {
        fprintf( stderr, "Warning: The certificate specifies no KEYUSAGE.\n"
                         "Cryptlib may not permit its use. See "
                         "<http://toroid.org/ams/pemtrans>.\n" );
    }

    n = cryptKeysetOpen( &keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                         outFile, opt );
    check( n, keyset, "cryptKeysetOpen" );

    n = cryptAddPrivateKey( keyset, pKey, secret );
    check( n, keyset, "cryptAddPrivateKey" );
    n = cryptAddPublicKey( keyset, cert );
    check( n, keyset, "cryptAddPublicKey" );

    cryptKeysetClose( keyset );
    cryptDestroyComponents( &rsa );
    cryptDestroyContext( pKey );
    cryptDestroyCert( cert );
    exit( 0 );
}
