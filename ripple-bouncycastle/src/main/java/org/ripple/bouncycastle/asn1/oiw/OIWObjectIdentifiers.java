package org.ripple.bouncycastle.asn1.oiw;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface oiwobjectidentifiers
{
    // id-sha1 object identifier ::=    
    //   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }    //
    static final asn1objectidentifier    md4withrsa              = new asn1objectidentifier("1.3.14.3.2.2");
    static final asn1objectidentifier    md5withrsa              = new asn1objectidentifier("1.3.14.3.2.3");
    static final asn1objectidentifier    md4withrsaencryption    = new asn1objectidentifier("1.3.14.3.2.4");
    
    static final asn1objectidentifier    desecb                  = new asn1objectidentifier("1.3.14.3.2.6");
    static final asn1objectidentifier    descbc                  = new asn1objectidentifier("1.3.14.3.2.7");
    static final asn1objectidentifier    desofb                  = new asn1objectidentifier("1.3.14.3.2.8");
    static final asn1objectidentifier    descfb                  = new asn1objectidentifier("1.3.14.3.2.9");

    static final asn1objectidentifier    desede                  = new asn1objectidentifier("1.3.14.3.2.17");
    
    static final asn1objectidentifier    idsha1                  = new asn1objectidentifier("1.3.14.3.2.26");

    static final asn1objectidentifier    dsawithsha1             = new asn1objectidentifier("1.3.14.3.2.27");

    static final asn1objectidentifier    sha1withrsa             = new asn1objectidentifier("1.3.14.3.2.29");
    
    // elgamal algorithm object identifier ::=    
    // {iso(1) identified-organization(3) oiw(14) dirservsig(7) algorithm(2) encryption(1) 1 }
    //
    static final asn1objectidentifier    elgamalalgorithm        = new asn1objectidentifier("1.3.14.7.2.1.1");

}
