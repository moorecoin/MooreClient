package org.ripple.bouncycastle.asn1.icao;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface icaoobjectidentifiers
{
    //
    // base id
    //
    static final asn1objectidentifier    id_icao                   = new asn1objectidentifier("2.23.136");

    static final asn1objectidentifier    id_icao_mrtd              = id_icao.branch("1");
    static final asn1objectidentifier    id_icao_mrtd_security     = id_icao_mrtd.branch("1");

    // lds security object, see icao doc 9303-volume 2-section iv-a3.2
    static final asn1objectidentifier    id_icao_ldssecurityobject = id_icao_mrtd_security.branch("1");

    // csca master list, see tr csca countersigning and master list issuance
    static final asn1objectidentifier    id_icao_cscamasterlist    = id_icao_mrtd_security.branch("2");
    static final asn1objectidentifier    id_icao_cscamasterlistsigningkey = id_icao_mrtd_security.branch("3");

    // document type list, see draft tr lds and pki maintenance, par. 3.2.1
    static final asn1objectidentifier    id_icao_documenttypelist  = id_icao_mrtd_security.branch("4");

    // active authentication protocol, see draft tr lds and pki maintenance,
    // par. 5.2.2
    static final asn1objectidentifier    id_icao_aaprotocolobject  = id_icao_mrtd_security.branch("5");

    // csca name change and key reoll-over, see draft tr lds and pki
    // maintenance, par. 3.2.1
    static final asn1objectidentifier    id_icao_extensions        = id_icao_mrtd_security.branch("6");
    static final asn1objectidentifier    id_icao_extensions_namechangekeyrollover = id_icao_extensions.branch("1");
}
