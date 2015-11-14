package org.ripple.bouncycastle.asn1.bc;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface bcobjectidentifiers
{
    /**
     *  iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
     *
     *  1.3.6.1.4.1.22554
     */
    public static final asn1objectidentifier bc = new asn1objectidentifier("1.3.6.1.4.1.22554");

    /**
     * pbe(1) algorithms
     */
    public static final asn1objectidentifier bc_pbe = new asn1objectidentifier(bc.getid() + ".1");

    /**
     * sha-1(1)
     */
    public static final asn1objectidentifier bc_pbe_sha1 = new asn1objectidentifier(bc_pbe.getid() + ".1");

    /**
     * sha-2(2) . (sha-256(1)|sha-384(2)|sha-512(3)|sha-224(4))
     */
    public static final asn1objectidentifier bc_pbe_sha256 = new asn1objectidentifier(bc_pbe.getid() + ".2.1");
    public static final asn1objectidentifier bc_pbe_sha384 = new asn1objectidentifier(bc_pbe.getid() + ".2.2");
    public static final asn1objectidentifier bc_pbe_sha512 = new asn1objectidentifier(bc_pbe.getid() + ".2.3");
    public static final asn1objectidentifier bc_pbe_sha224 = new asn1objectidentifier(bc_pbe.getid() + ".2.4");

    /**
     * pkcs-5(1)|pkcs-12(2)
     */
    public static final asn1objectidentifier bc_pbe_sha1_pkcs5 = new asn1objectidentifier(bc_pbe_sha1.getid() + ".1");
    public static final asn1objectidentifier bc_pbe_sha1_pkcs12 = new asn1objectidentifier(bc_pbe_sha1.getid() + ".2");

    public static final asn1objectidentifier bc_pbe_sha256_pkcs5 = new asn1objectidentifier(bc_pbe_sha256.getid() + ".1");
    public static final asn1objectidentifier bc_pbe_sha256_pkcs12 = new asn1objectidentifier(bc_pbe_sha256.getid() + ".2");

    /**
     * aes(1) . (cbc-128(2)|cbc-192(22)|cbc-256(42))
     */
    public static final asn1objectidentifier bc_pbe_sha1_pkcs12_aes128_cbc = new asn1objectidentifier(bc_pbe_sha1_pkcs12.getid() + ".1.2");
    public static final asn1objectidentifier bc_pbe_sha1_pkcs12_aes192_cbc = new asn1objectidentifier(bc_pbe_sha1_pkcs12.getid() + ".1.22");
    public static final asn1objectidentifier bc_pbe_sha1_pkcs12_aes256_cbc = new asn1objectidentifier(bc_pbe_sha1_pkcs12.getid() + ".1.42");

    public static final asn1objectidentifier bc_pbe_sha256_pkcs12_aes128_cbc = new asn1objectidentifier(bc_pbe_sha256_pkcs12.getid() + ".1.2");
    public static final asn1objectidentifier bc_pbe_sha256_pkcs12_aes192_cbc = new asn1objectidentifier(bc_pbe_sha256_pkcs12.getid() + ".1.22");
    public static final asn1objectidentifier bc_pbe_sha256_pkcs12_aes256_cbc = new asn1objectidentifier(bc_pbe_sha256_pkcs12.getid() + ".1.42");
}
