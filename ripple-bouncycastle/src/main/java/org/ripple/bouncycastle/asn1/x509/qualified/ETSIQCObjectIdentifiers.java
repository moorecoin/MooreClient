package org.ripple.bouncycastle.asn1.x509.qualified;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface etsiqcobjectidentifiers
{
    //
    // base id
    //
    static final asn1objectidentifier    id_etsi_qcs                  = new asn1objectidentifier("0.4.0.1862.1");

    static final asn1objectidentifier    id_etsi_qcs_qccompliance     = id_etsi_qcs.branch("1");
    static final asn1objectidentifier    id_etsi_qcs_limitevalue      = id_etsi_qcs.branch("2");
    static final asn1objectidentifier    id_etsi_qcs_retentionperiod  = id_etsi_qcs.branch("3");
    static final asn1objectidentifier    id_etsi_qcs_qcsscd           = id_etsi_qcs.branch("4");
}
