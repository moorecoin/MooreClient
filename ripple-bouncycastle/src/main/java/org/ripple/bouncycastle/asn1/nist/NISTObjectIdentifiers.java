package org.ripple.bouncycastle.asn1.nist;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface nistobjectidentifiers
{
    //
    // nist
    //     iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3) 

    //
    // nistalgorithms(4)
    //
    static final asn1objectidentifier    nistalgorithm           = new asn1objectidentifier("2.16.840.1.101.3.4");

    static final asn1objectidentifier    hashalgs                = nistalgorithm.branch("2");

    static final asn1objectidentifier    id_sha256               = hashalgs.branch("1");
    static final asn1objectidentifier    id_sha384               = hashalgs.branch("2");
    static final asn1objectidentifier    id_sha512               = hashalgs.branch("3");
    static final asn1objectidentifier    id_sha224               = hashalgs.branch("4");
    static final asn1objectidentifier    id_sha512_224           = hashalgs.branch("5");
    static final asn1objectidentifier    id_sha512_256           = hashalgs.branch("6");

    static final asn1objectidentifier    aes                     =  nistalgorithm.branch("1");
    
    static final asn1objectidentifier    id_aes128_ecb           = aes.branch("1"); 
    static final asn1objectidentifier    id_aes128_cbc           = aes.branch("2");
    static final asn1objectidentifier    id_aes128_ofb           = aes.branch("3"); 
    static final asn1objectidentifier    id_aes128_cfb           = aes.branch("4"); 
    static final asn1objectidentifier    id_aes128_wrap          = aes.branch("5");
    static final asn1objectidentifier    id_aes128_gcm           = aes.branch("6");
    static final asn1objectidentifier    id_aes128_ccm           = aes.branch("7");
    
    static final asn1objectidentifier    id_aes192_ecb           = aes.branch("21"); 
    static final asn1objectidentifier    id_aes192_cbc           = aes.branch("22"); 
    static final asn1objectidentifier    id_aes192_ofb           = aes.branch("23"); 
    static final asn1objectidentifier    id_aes192_cfb           = aes.branch("24"); 
    static final asn1objectidentifier    id_aes192_wrap          = aes.branch("25");
    static final asn1objectidentifier    id_aes192_gcm           = aes.branch("26");
    static final asn1objectidentifier    id_aes192_ccm           = aes.branch("27");
    
    static final asn1objectidentifier    id_aes256_ecb           = aes.branch("41"); 
    static final asn1objectidentifier    id_aes256_cbc           = aes.branch("42");
    static final asn1objectidentifier    id_aes256_ofb           = aes.branch("43"); 
    static final asn1objectidentifier    id_aes256_cfb           = aes.branch("44"); 
    static final asn1objectidentifier    id_aes256_wrap          = aes.branch("45"); 
    static final asn1objectidentifier    id_aes256_gcm           = aes.branch("46");
    static final asn1objectidentifier    id_aes256_ccm           = aes.branch("47");

    //
    // signatures
    //
    static final asn1objectidentifier    id_dsa_with_sha2        = nistalgorithm.branch("3");

    static final asn1objectidentifier    dsa_with_sha224         = id_dsa_with_sha2.branch("1");
    static final asn1objectidentifier    dsa_with_sha256         = id_dsa_with_sha2.branch("2");
    static final asn1objectidentifier    dsa_with_sha384         = id_dsa_with_sha2.branch("3");
    static final asn1objectidentifier    dsa_with_sha512         = id_dsa_with_sha2.branch("4");
}
