package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface x509attributeidentifiers
{
    /**
     * @deprecated use id_at_role
     */
    static final asn1objectidentifier rolesyntax = new asn1objectidentifier("2.5.4.72");

    static final asn1objectidentifier id_pe_ac_auditidentity = x509objectidentifiers.id_pe.branch("4");
    static final asn1objectidentifier id_pe_aacontrols       = x509objectidentifiers.id_pe.branch("6");
    static final asn1objectidentifier id_pe_ac_proxying      = x509objectidentifiers.id_pe.branch("10");

    static final asn1objectidentifier id_ce_targetinformation= x509objectidentifiers.id_ce.branch("55");

    static final asn1objectidentifier id_aca = x509objectidentifiers.id_pkix.branch("10");

    static final asn1objectidentifier id_aca_authenticationinfo    = id_aca.branch("1");
    static final asn1objectidentifier id_aca_accessidentity        = id_aca.branch("2");
    static final asn1objectidentifier id_aca_chargingidentity      = id_aca.branch("3");
    static final asn1objectidentifier id_aca_group                 = id_aca.branch("4");
    // { id-aca 5 } is reserved
    static final asn1objectidentifier id_aca_encattrs              = id_aca.branch("6");

    static final asn1objectidentifier id_at_role = new asn1objectidentifier("2.5.4.72");
    static final asn1objectidentifier id_at_clearance = new asn1objectidentifier("2.5.1.5.55");
}
