package org.ripple.bouncycastle.asn1.ntt;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

/**
 * from rfc 3657
 */
public interface nttobjectidentifiers
{
    public static final asn1objectidentifier id_camellia128_cbc = new asn1objectidentifier("1.2.392.200011.61.1.1.1.2");
    public static final asn1objectidentifier id_camellia192_cbc = new asn1objectidentifier("1.2.392.200011.61.1.1.1.3");
    public static final asn1objectidentifier id_camellia256_cbc = new asn1objectidentifier("1.2.392.200011.61.1.1.1.4");

    public static final asn1objectidentifier id_camellia128_wrap = new asn1objectidentifier("1.2.392.200011.61.1.1.3.2");
    public static final asn1objectidentifier id_camellia192_wrap = new asn1objectidentifier("1.2.392.200011.61.1.1.3.3");
    public static final asn1objectidentifier id_camellia256_wrap = new asn1objectidentifier("1.2.392.200011.61.1.1.3.4");
}
