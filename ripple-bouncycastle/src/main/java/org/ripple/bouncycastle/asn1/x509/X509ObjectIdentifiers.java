package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface x509objectidentifiers
{
    //
    // base id
    //
    static final string                 id                      = "2.5.4";

    static final asn1objectidentifier    commonname              = new asn1objectidentifier(id + ".3");
    static final asn1objectidentifier    countryname             = new asn1objectidentifier(id + ".6");
    static final asn1objectidentifier    localityname            = new asn1objectidentifier(id + ".7");
    static final asn1objectidentifier    stateorprovincename     = new asn1objectidentifier(id + ".8");
    static final asn1objectidentifier    organization            = new asn1objectidentifier(id + ".10");
    static final asn1objectidentifier    organizationalunitname  = new asn1objectidentifier(id + ".11");

    static final asn1objectidentifier    id_at_telephonenumber   = new asn1objectidentifier("2.5.4.20");
    static final asn1objectidentifier    id_at_name              = new asn1objectidentifier(id + ".41");

    // id-sha1 object identifier ::=    
    //   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }    //
    static final asn1objectidentifier    id_sha1                 = new asn1objectidentifier("1.3.14.3.2.26");

    //
    // ripemd160 object identifier ::=
    //      {iso(1) identified-organization(3) teletrust(36) algorithm(3) hashalgorithm(2) ripemd-160(1)}
    //
    static final asn1objectidentifier    ripemd160               = new asn1objectidentifier("1.3.36.3.2.1");

    //
    // ripemd160withrsaencryption object identifier ::=
    //      {iso(1) identified-organization(3) teletrust(36) algorithm(3) signaturealgorithm(3) rsasignature(1) rsasignaturewithripemd160(2) }
    //
    static final asn1objectidentifier    ripemd160withrsaencryption = new asn1objectidentifier("1.3.36.3.3.1.2");


    static final asn1objectidentifier    id_ea_rsa = new asn1objectidentifier("2.5.8.1.1");
    
    // id-pkix
    static final asn1objectidentifier id_pkix = new asn1objectidentifier("1.3.6.1.5.5.7");

    //
    // private internet extensions
    //
    static final asn1objectidentifier  id_pe = new asn1objectidentifier(id_pkix + ".1");

    //
    // iso arc for standard certificate and crl extensions
    //
    static final asn1objectidentifier id_ce = new asn1objectidentifier("2.5.29");

    //
    // authority information access
    //
    static final asn1objectidentifier  id_ad = new asn1objectidentifier(id_pkix + ".48");
    static final asn1objectidentifier  id_ad_caissuers = new asn1objectidentifier(id_ad + ".2");
    static final asn1objectidentifier  id_ad_ocsp = new asn1objectidentifier(id_ad + ".1");

    //
    //    oid for ocsp and crl uri in authorityinformationaccess extension
    //
    static final asn1objectidentifier ocspaccessmethod = id_ad_ocsp;
    static final asn1objectidentifier crlaccessmethod = id_ad_caissuers;
}

