package org.ripple.bouncycastle.asn1.x509.qualified;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface rfc3739qcobjectidentifiers
{
    //
    // base id
    //
    static final asn1objectidentifier   id_qcs             = new asn1objectidentifier("1.3.6.1.5.5.7.11");

    static final asn1objectidentifier   id_qcs_pkixqcsyntax_v1  = id_qcs.branch("1");
    static final asn1objectidentifier   id_qcs_pkixqcsyntax_v2  = id_qcs.branch("2");
}
