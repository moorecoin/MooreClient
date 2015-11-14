package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public interface crmfobjectidentifiers
{
    static final asn1objectidentifier id_pkix = new asn1objectidentifier("1.3.6.1.5.5.7");

    // arc for internet x.509 pki protocols and their components

    static final asn1objectidentifier id_pkip  = id_pkix.branch("5");

    static final asn1objectidentifier id_regctrl = id_pkip.branch("1");
    static final asn1objectidentifier id_regctrl_regtoken = id_regctrl.branch("1");
    static final asn1objectidentifier id_regctrl_authenticator = id_regctrl.branch("2");
    static final asn1objectidentifier id_regctrl_pkipublicationinfo = id_regctrl.branch("3");
    static final asn1objectidentifier id_regctrl_pkiarchiveoptions = id_regctrl.branch("4");

    static final asn1objectidentifier id_ct_enckeywithid = new asn1objectidentifier(pkcsobjectidentifiers.id_ct + ".21");
}
