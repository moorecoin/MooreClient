package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface ocspobjectidentifiers
{
    public static final string pkix_ocsp = "1.3.6.1.5.5.7.48.1";

    public static final asn1objectidentifier id_pkix_ocsp = new asn1objectidentifier(pkix_ocsp);
    public static final asn1objectidentifier id_pkix_ocsp_basic = new asn1objectidentifier(pkix_ocsp + ".1");
    
    //
    // extensions
    //
    public static final asn1objectidentifier id_pkix_ocsp_nonce = new asn1objectidentifier(pkix_ocsp + ".2");
    public static final asn1objectidentifier id_pkix_ocsp_crl = new asn1objectidentifier(pkix_ocsp + ".3");
    
    public static final asn1objectidentifier id_pkix_ocsp_response = new asn1objectidentifier(pkix_ocsp + ".4");
    public static final asn1objectidentifier id_pkix_ocsp_nocheck = new asn1objectidentifier(pkix_ocsp + ".5");
    public static final asn1objectidentifier id_pkix_ocsp_archive_cutoff = new asn1objectidentifier(pkix_ocsp + ".6");
    public static final asn1objectidentifier id_pkix_ocsp_service_locator = new asn1objectidentifier(pkix_ocsp + ".7");
}
