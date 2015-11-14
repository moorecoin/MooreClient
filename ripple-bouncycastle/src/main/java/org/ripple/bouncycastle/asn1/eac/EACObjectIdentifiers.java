package org.ripple.bouncycastle.asn1.eac;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface eacobjectidentifiers
{
    // bsi-de object identifier ::= {
    //         itu-t(0) identified-organization(4) etsi(0)
    //         reserved(127) etsi-identified-organization(0) 7
    //     }
    static final asn1objectidentifier    bsi_de      = new asn1objectidentifier("0.4.0.127.0.7");

    // id-pk object identifier ::= {
    //         bsi-de protocols(2) smartcard(2) 1
    //     }
    static final asn1objectidentifier    id_pk = bsi_de.branch("2.2.1");

    static final asn1objectidentifier    id_pk_dh = id_pk.branch("1");
    static final asn1objectidentifier    id_pk_ecdh = id_pk.branch("2");

    // id-ca object identifier ::= {
    //         bsi-de protocols(2) smartcard(2) 3
    //     }
    static final asn1objectidentifier    id_ca = bsi_de.branch("2.2.3");
    static final asn1objectidentifier    id_ca_dh = id_ca.branch("1");
    static final asn1objectidentifier    id_ca_dh_3des_cbc_cbc = id_ca_dh.branch("1");
    static final asn1objectidentifier    id_ca_ecdh = id_ca.branch("2");
    static final asn1objectidentifier    id_ca_ecdh_3des_cbc_cbc = id_ca_ecdh.branch("1");

    //
    // id-ta object identifier ::= {
    //     bsi-de protocols(2) smartcard(2) 2
    // }
    static final asn1objectidentifier    id_ta = bsi_de.branch("2.2.2");

    static final asn1objectidentifier    id_ta_rsa = id_ta.branch("1");
    static final asn1objectidentifier    id_ta_rsa_v1_5_sha_1 = id_ta_rsa .branch("1");
    static final asn1objectidentifier    id_ta_rsa_v1_5_sha_256 = id_ta_rsa.branch("2");
    static final asn1objectidentifier    id_ta_rsa_pss_sha_1 = id_ta_rsa.branch("3");
    static final asn1objectidentifier    id_ta_rsa_pss_sha_256 = id_ta_rsa.branch("4");
    static final asn1objectidentifier    id_ta_rsa_v1_5_sha_512 = id_ta_rsa.branch("5");
    static final asn1objectidentifier    id_ta_rsa_pss_sha_512 = id_ta_rsa.branch("6");
    static final asn1objectidentifier    id_ta_ecdsa = id_ta.branch("2");
    static final asn1objectidentifier    id_ta_ecdsa_sha_1 = id_ta_ecdsa.branch("1");
    static final asn1objectidentifier    id_ta_ecdsa_sha_224 = id_ta_ecdsa.branch("2");
    static final asn1objectidentifier    id_ta_ecdsa_sha_256 = id_ta_ecdsa.branch("3");
    static final asn1objectidentifier    id_ta_ecdsa_sha_384 = id_ta_ecdsa.branch("4");
    static final asn1objectidentifier    id_ta_ecdsa_sha_512 = id_ta_ecdsa.branch("5");

    /**
     * id-eac-epassport object identifier ::= {
     * bsi-de applications(3) mrtd(1) roles(2) 1}
     */
    static final asn1objectidentifier id_eac_epassport = bsi_de.branch("3.1.2.1");
}
