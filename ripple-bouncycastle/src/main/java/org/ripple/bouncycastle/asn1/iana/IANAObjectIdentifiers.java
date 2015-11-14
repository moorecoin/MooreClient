package org.ripple.bouncycastle.asn1.iana;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface ianaobjectidentifiers
{
    // id-sha1 object identifier ::=    
    // {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ipsec(8) isakmpoakley(1)}
    //

    static final asn1objectidentifier    isakmpoakley  = new asn1objectidentifier("1.3.6.1.5.5.8.1");

    static final asn1objectidentifier    hmacmd5       = new asn1objectidentifier(isakmpoakley + ".1");
    static final asn1objectidentifier    hmacsha1     = new asn1objectidentifier(isakmpoakley + ".2");
    
    static final asn1objectidentifier    hmactiger     = new asn1objectidentifier(isakmpoakley + ".3");
    
    static final asn1objectidentifier    hmacripemd160 = new asn1objectidentifier(isakmpoakley + ".4");

}
