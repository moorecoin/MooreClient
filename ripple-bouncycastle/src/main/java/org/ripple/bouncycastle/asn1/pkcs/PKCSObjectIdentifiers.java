package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface pkcsobjectidentifiers
{
    //
    // pkcs-1 object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
    //
    static final asn1objectidentifier    pkcs_1                    = new asn1objectidentifier("1.2.840.113549.1.1");
    static final asn1objectidentifier    rsaencryption             = pkcs_1.branch("1");
    static final asn1objectidentifier    md2withrsaencryption      = pkcs_1.branch("2");
    static final asn1objectidentifier    md4withrsaencryption      = pkcs_1.branch("3");
    static final asn1objectidentifier    md5withrsaencryption      = pkcs_1.branch("4");
    static final asn1objectidentifier    sha1withrsaencryption     = pkcs_1.branch("5");
    static final asn1objectidentifier    srsaoaepencryptionset     = pkcs_1.branch("6");
    static final asn1objectidentifier    id_rsaes_oaep             = pkcs_1.branch("7");
    static final asn1objectidentifier    id_mgf1                   = pkcs_1.branch("8");
    static final asn1objectidentifier    id_pspecified             = pkcs_1.branch("9");
    static final asn1objectidentifier    id_rsassa_pss             = pkcs_1.branch("10");
    static final asn1objectidentifier    sha256withrsaencryption   = pkcs_1.branch("11");
    static final asn1objectidentifier    sha384withrsaencryption   = pkcs_1.branch("12");
    static final asn1objectidentifier    sha512withrsaencryption   = pkcs_1.branch("13");
    static final asn1objectidentifier    sha224withrsaencryption   = pkcs_1.branch("14");

    //
    // pkcs-3 object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
    //
    static final asn1objectidentifier    pkcs_3                  = new asn1objectidentifier("1.2.840.113549.1.3");
    static final asn1objectidentifier    dhkeyagreement          = pkcs_3.branch("1");

    //
    // pkcs-5 object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
    //
    static final asn1objectidentifier    pkcs_5                  = new asn1objectidentifier("1.2.840.113549.1.5");

    static final asn1objectidentifier    pbewithmd2anddes_cbc    = pkcs_5.branch("1");
    static final asn1objectidentifier    pbewithmd2andrc2_cbc    = pkcs_5.branch("4");
    static final asn1objectidentifier    pbewithmd5anddes_cbc    = pkcs_5.branch("3");
    static final asn1objectidentifier    pbewithmd5andrc2_cbc    = pkcs_5.branch("6");
    static final asn1objectidentifier    pbewithsha1anddes_cbc   = pkcs_5.branch("10");
    static final asn1objectidentifier    pbewithsha1andrc2_cbc   = pkcs_5.branch("11");

    static final asn1objectidentifier    id_pbes2                = pkcs_5.branch("13");

    static final asn1objectidentifier    id_pbkdf2               = pkcs_5.branch("12");

    //
    // encryptionalgorithm object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
    //
    static final asn1objectidentifier    encryptionalgorithm     = new asn1objectidentifier("1.2.840.113549.3");

    static final asn1objectidentifier    des_ede3_cbc            = encryptionalgorithm.branch("7");
    static final asn1objectidentifier    rc2_cbc                 = encryptionalgorithm.branch("2");
    static final asn1objectidentifier    rc4                     = encryptionalgorithm.branch("4");

    //
    // object identifiers for digests
    //
    static final asn1objectidentifier    digestalgorithm        = new asn1objectidentifier("1.2.840.113549.2");
    //
    // md2 object identifier ::=
    //      {iso(1) member-body(2) us(840) rsadsi(113549) digestalgorithm(2) 2}
    //
    static final asn1objectidentifier    md2                    = digestalgorithm.branch("2");

    //
    // md4 object identifier ::=
    //      {iso(1) member-body(2) us(840) rsadsi(113549) digestalgorithm(2) 4}
    //
    static final asn1objectidentifier    md4 = digestalgorithm.branch("4");

    //
    // md5 object identifier ::=
    //      {iso(1) member-body(2) us(840) rsadsi(113549) digestalgorithm(2) 5}
    //
    static final asn1objectidentifier    md5                     = digestalgorithm.branch("5");

    static final asn1objectidentifier    id_hmacwithsha1         = digestalgorithm.branch("7");
    static final asn1objectidentifier    id_hmacwithsha224       = digestalgorithm.branch("8");
    static final asn1objectidentifier    id_hmacwithsha256       = digestalgorithm.branch("9");
    static final asn1objectidentifier    id_hmacwithsha384       = digestalgorithm.branch("10");
    static final asn1objectidentifier    id_hmacwithsha512       = digestalgorithm.branch("11");

    //
    // pkcs-7 object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
    //
    static final string                 pkcs_7                  = "1.2.840.113549.1.7";
    static final asn1objectidentifier    data                    = new asn1objectidentifier(pkcs_7 + ".1");
    static final asn1objectidentifier    signeddata              = new asn1objectidentifier(pkcs_7 + ".2");
    static final asn1objectidentifier    envelopeddata           = new asn1objectidentifier(pkcs_7 + ".3");
    static final asn1objectidentifier    signedandenvelopeddata  = new asn1objectidentifier(pkcs_7 + ".4");
    static final asn1objectidentifier    digesteddata            = new asn1objectidentifier(pkcs_7 + ".5");
    static final asn1objectidentifier    encrypteddata           = new asn1objectidentifier(pkcs_7 + ".6");

    //
    // pkcs-9 object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
    //
    static final asn1objectidentifier    pkcs_9                  = new asn1objectidentifier("1.2.840.113549.1.9");

    static final asn1objectidentifier    pkcs_9_at_emailaddress  = pkcs_9.branch("1");
    static final asn1objectidentifier    pkcs_9_at_unstructuredname = pkcs_9.branch("2");
    static final asn1objectidentifier    pkcs_9_at_contenttype = pkcs_9.branch("3");
    static final asn1objectidentifier    pkcs_9_at_messagedigest = pkcs_9.branch("4");
    static final asn1objectidentifier    pkcs_9_at_signingtime = pkcs_9.branch("5");
    static final asn1objectidentifier    pkcs_9_at_countersignature = pkcs_9.branch("6");
    static final asn1objectidentifier    pkcs_9_at_challengepassword = pkcs_9.branch("7");
    static final asn1objectidentifier    pkcs_9_at_unstructuredaddress = pkcs_9.branch("8");
    static final asn1objectidentifier    pkcs_9_at_extendedcertificateattributes = pkcs_9.branch("9");

    static final asn1objectidentifier    pkcs_9_at_signingdescription = pkcs_9.branch("13");
    static final asn1objectidentifier    pkcs_9_at_extensionrequest = pkcs_9.branch("14");
    static final asn1objectidentifier    pkcs_9_at_smimecapabilities = pkcs_9.branch("15");

    static final asn1objectidentifier    pkcs_9_at_friendlyname  = pkcs_9.branch("20");
    static final asn1objectidentifier    pkcs_9_at_localkeyid    = pkcs_9.branch("21");

    /** @deprecated use x509certificate instead */
    static final asn1objectidentifier    x509certtype            = pkcs_9.branch("22.1");

    static final asn1objectidentifier    certtypes               = pkcs_9.branch("22");
    static final asn1objectidentifier    x509certificate         = certtypes.branch("1");
    static final asn1objectidentifier    sdsicertificate         = certtypes.branch("2");

    static final asn1objectidentifier    crltypes                = pkcs_9.branch("23");
    static final asn1objectidentifier    x509crl                 = crltypes.branch("1");

    static final asn1objectidentifier    id_alg_pwri_kek    = pkcs_9.branch("16.3.9");

    //
    // smime capability sub oids.
    //
    static final asn1objectidentifier    prefersigneddata        = pkcs_9.branch("15.1");
    static final asn1objectidentifier    cannotdecryptany        = pkcs_9.branch("15.2");
    static final asn1objectidentifier    smimecapabilitiesversions = pkcs_9.branch("15.3");

    //
    // id-ct object identifier ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
    //
    static final asn1objectidentifier    id_ct = new asn1objectidentifier("1.2.840.113549.1.9.16.1");

    static final asn1objectidentifier    id_ct_authdata          = id_ct.branch("2");
    static final asn1objectidentifier    id_ct_tstinfo           = id_ct.branch("4");
    static final asn1objectidentifier    id_ct_compresseddata    = id_ct.branch("9");
    static final asn1objectidentifier    id_ct_authenvelopeddata = id_ct.branch("23");
    static final asn1objectidentifier    id_ct_timestampeddata   = id_ct.branch("31");

    //
    // id-cti object identifier ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
    //
    static final asn1objectidentifier    id_cti = new asn1objectidentifier("1.2.840.113549.1.9.16.6");
    
    static final asn1objectidentifier    id_cti_ets_proofoforigin  = id_cti.branch("1");
    static final asn1objectidentifier    id_cti_ets_proofofreceipt = id_cti.branch("2");
    static final asn1objectidentifier    id_cti_ets_proofofdelivery = id_cti.branch("3");
    static final asn1objectidentifier    id_cti_ets_proofofsender = id_cti.branch("4");
    static final asn1objectidentifier    id_cti_ets_proofofapproval = id_cti.branch("5");
    static final asn1objectidentifier    id_cti_ets_proofofcreation = id_cti.branch("6");
    
    //
    // id-aa object identifier ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
    //
    static final asn1objectidentifier    id_aa = new asn1objectidentifier("1.2.840.113549.1.9.16.2");


    static final asn1objectidentifier id_aa_receiptrequest = id_aa.branch("1");
    
    static final asn1objectidentifier id_aa_contenthint = id_aa.branch("4"); // see rfc 2634
    static final asn1objectidentifier id_aa_msgsigdigest = id_aa.branch("5");
    static final asn1objectidentifier id_aa_contentreference = id_aa.branch("10");
    /*
     * id-aa-encrypkeypref object identifier ::= {id-aa 11}
     * 
     */
    static final asn1objectidentifier id_aa_encrypkeypref = id_aa.branch("11");
    static final asn1objectidentifier id_aa_signingcertificate = id_aa.branch("12");
    static final asn1objectidentifier id_aa_signingcertificatev2 = id_aa.branch("47");

    static final asn1objectidentifier id_aa_contentidentifier = id_aa.branch("7"); // see rfc 2634

    /*
     * rfc 3126
     */
    static final asn1objectidentifier id_aa_signaturetimestamptoken = id_aa.branch("14");
    
    static final asn1objectidentifier id_aa_ets_sigpolicyid = id_aa.branch("15");
    static final asn1objectidentifier id_aa_ets_commitmenttype = id_aa.branch("16");
    static final asn1objectidentifier id_aa_ets_signerlocation = id_aa.branch("17");
    static final asn1objectidentifier id_aa_ets_signerattr = id_aa.branch("18");
    static final asn1objectidentifier id_aa_ets_othersigcert = id_aa.branch("19");
    static final asn1objectidentifier id_aa_ets_contenttimestamp = id_aa.branch("20");
    static final asn1objectidentifier id_aa_ets_certificaterefs = id_aa.branch("21");
    static final asn1objectidentifier id_aa_ets_revocationrefs = id_aa.branch("22");
    static final asn1objectidentifier id_aa_ets_certvalues = id_aa.branch("23");
    static final asn1objectidentifier id_aa_ets_revocationvalues = id_aa.branch("24");
    static final asn1objectidentifier id_aa_ets_esctimestamp = id_aa.branch("25");
    static final asn1objectidentifier id_aa_ets_certcrltimestamp = id_aa.branch("26");
    static final asn1objectidentifier id_aa_ets_archivetimestamp = id_aa.branch("27");

    /** @deprecated use id_aa_ets_sigpolicyid instead */
    static final asn1objectidentifier id_aa_sigpolicyid = id_aa_ets_sigpolicyid;
    /** @deprecated use id_aa_ets_commitmenttype instead */
    static final asn1objectidentifier id_aa_commitmenttype = id_aa_ets_commitmenttype;
    /** @deprecated use id_aa_ets_signerlocation instead */
    static final asn1objectidentifier id_aa_signerlocation = id_aa_ets_signerlocation;
    /** @deprecated use id_aa_ets_othersigcert instead */
    static final asn1objectidentifier id_aa_othersigcert = id_aa_ets_othersigcert;
    
    //
    // id-spq object identifier ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-spq(5)}
    //
    final string id_spq = "1.2.840.113549.1.9.16.5";

    static final asn1objectidentifier id_spq_ets_uri = new asn1objectidentifier(id_spq + ".1");
    static final asn1objectidentifier id_spq_ets_unotice = new asn1objectidentifier(id_spq + ".2");

    //
    // pkcs-12 object identifier ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
    //
    static final asn1objectidentifier   pkcs_12                  = new asn1objectidentifier("1.2.840.113549.1.12");
    static final asn1objectidentifier   bagtypes                 = pkcs_12.branch("10.1");

    static final asn1objectidentifier    keybag                  = bagtypes.branch("1");
    static final asn1objectidentifier    pkcs8shroudedkeybag     = bagtypes.branch("2");
    static final asn1objectidentifier    certbag                 = bagtypes.branch("3");
    static final asn1objectidentifier    crlbag                  = bagtypes.branch("4");
    static final asn1objectidentifier    secretbag               = bagtypes.branch("5");
    static final asn1objectidentifier    safecontentsbag         = bagtypes.branch("6");

    static final asn1objectidentifier    pkcs_12pbeids  = pkcs_12.branch("1");

    static final asn1objectidentifier    pbewithshaand128bitrc4 = pkcs_12pbeids.branch("1");
    static final asn1objectidentifier    pbewithshaand40bitrc4  = pkcs_12pbeids.branch("2");
    static final asn1objectidentifier    pbewithshaand3_keytripledes_cbc = pkcs_12pbeids.branch("3");
    static final asn1objectidentifier    pbewithshaand2_keytripledes_cbc = pkcs_12pbeids.branch("4");
    static final asn1objectidentifier    pbewithshaand128bitrc2_cbc = pkcs_12pbeids.branch("5");
    static final asn1objectidentifier    pbewithshaand40bitrc2_cbc = pkcs_12pbeids.branch("6");

    /**
     * @deprecated use pbewithshaand40bitrc2_cbc
     */
    static final asn1objectidentifier    pbewithshaand40bitrc2_cbc = pkcs_12pbeids.branch("6");

    static final asn1objectidentifier    id_alg_cms3deswrap = new asn1objectidentifier("1.2.840.113549.1.9.16.3.6");
    static final asn1objectidentifier    id_alg_cmsrc2wrap = new asn1objectidentifier("1.2.840.113549.1.9.16.3.7");
}

