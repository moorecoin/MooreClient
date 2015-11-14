package org.ripple.bouncycastle.asn1.microsoft;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface microsoftobjectidentifiers
{
    //
    // microsoft
    //       iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) microsoft(311)
    //
    static final asn1objectidentifier    microsoft               = new asn1objectidentifier("1.3.6.1.4.1.311");
    static final asn1objectidentifier    microsoftcerttemplatev1 = microsoft.branch("20.2");
    static final asn1objectidentifier    microsoftcaversion      = microsoft.branch("21.1");
    static final asn1objectidentifier    microsoftprevcacerthash = microsoft.branch("21.2");
    static final asn1objectidentifier    microsoftcerttemplatev2 = microsoft.branch("21.7");
    static final asn1objectidentifier    microsoftapppolicies    = microsoft.branch("21.10");
}
