package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface dvcsobjectidentifiers
{

    //    id-pkix     object identifier ::= {iso(1)
    //                   identified-organization(3) dod(6)
    //                   internet(1) security(5) mechanisms(5) pkix(7)}
    //
    //    id-smime    object identifier ::= { iso(1) member-body(2)
    //                   us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 16 }
    public static final asn1objectidentifier id_pkix = new asn1objectidentifier("1.3.6.1.5.5.7");
    public static final asn1objectidentifier id_smime = new asn1objectidentifier("1.2.840.113549.1.9.16");

    //    -- authority information access for dvcs
    //
    //    id-ad-dvcs  object identifier ::= {id-pkix id-ad(48) 4}
    public static final asn1objectidentifier id_ad_dvcs = id_pkix.branch("48.4");

    //    -- key purpose for dvcs
    //
    //    id-kp-dvcs  object identifier ::= {id-pkix id-kp(3) 10}
    public static final asn1objectidentifier id_kp_dvcs = id_pkix.branch("3.10");

    //    id-ct-dvcsrequestdata  object identifier ::= { id-smime ct(1) 7 }
    //    id-ct-dvcsresponsedata object identifier ::= { id-smime ct(1) 8 }
    public static final asn1objectidentifier id_ct_dvcsrequestdata = id_smime.branch("1.7");
    public static final asn1objectidentifier id_ct_dvcsresponsedata = id_smime.branch("1.8");

    //    -- data validation certificate attribute
    //
    //    id-aa-dvcs-dvc object identifier ::= { id-smime aa(2) 29 }
    public static final asn1objectidentifier id_aa_dvcs_dvc = id_smime.branch("2.29");
}
