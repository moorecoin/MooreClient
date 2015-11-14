package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public interface cmsobjectidentifiers
{
    static final asn1objectidentifier    data = pkcsobjectidentifiers.data;
    static final asn1objectidentifier    signeddata = pkcsobjectidentifiers.signeddata;
    static final asn1objectidentifier    envelopeddata = pkcsobjectidentifiers.envelopeddata;
    static final asn1objectidentifier    signedandenvelopeddata = pkcsobjectidentifiers.signedandenvelopeddata;
    static final asn1objectidentifier    digesteddata = pkcsobjectidentifiers.digesteddata;
    static final asn1objectidentifier    encrypteddata = pkcsobjectidentifiers.encrypteddata;
    static final asn1objectidentifier    authenticateddata = pkcsobjectidentifiers.id_ct_authdata;
    static final asn1objectidentifier    compresseddata = pkcsobjectidentifiers.id_ct_compresseddata;
    static final asn1objectidentifier    authenvelopeddata = pkcsobjectidentifiers.id_ct_authenvelopeddata;
    static final asn1objectidentifier    timestampeddata = pkcsobjectidentifiers.id_ct_timestampeddata;

    /**
     * the other revocation info arc
     * id-ri object identifier ::= { iso(1) identified-organization(3)
     *                                   dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
     */
    static final asn1objectidentifier    id_ri = new asn1objectidentifier("1.3.6.1.5.5.7.16");

    static final asn1objectidentifier    id_ri_ocsp_response = id_ri.branch("2");
    static final asn1objectidentifier    id_ri_scvp = id_ri.branch("4");
}
