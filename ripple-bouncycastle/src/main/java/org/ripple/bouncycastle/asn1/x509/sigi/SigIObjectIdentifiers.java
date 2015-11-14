package org.ripple.bouncycastle.asn1.x509.sigi;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

/**
 * object identifiers of sigi specifciation (german signature law
 * interoperability specification).
 */
public interface sigiobjectidentifiers
{
    public final static asn1objectidentifier id_sigi = new asn1objectidentifier("1.3.36.8");

    /**
     * key purpose ids for german sigi (signature interoperability
     * specification)
     */
    public final static asn1objectidentifier id_sigi_kp = new asn1objectidentifier(id_sigi + ".2");

    /**
     * certificate policy ids for german sigi (signature interoperability
     * specification)
     */
    public final static asn1objectidentifier id_sigi_cp = new asn1objectidentifier(id_sigi + ".1");

    /**
     * other name ids for german sigi (signature interoperability specification)
     */
    public final static asn1objectidentifier id_sigi_on = new asn1objectidentifier(id_sigi + ".4");

    /**
     * to be used for for the generation of directory service certificates.
     */
    public static final asn1objectidentifier id_sigi_kp_directoryservice = new asn1objectidentifier(id_sigi_kp + ".1");

    /**
     * id for personaldata
     */
    public static final asn1objectidentifier id_sigi_on_personaldata = new asn1objectidentifier(id_sigi_on + ".1");

    /**
     * certificate is conform to german signature law.
     */
    public static final asn1objectidentifier id_sigi_cp_sigconform = new asn1objectidentifier(id_sigi_cp + ".1");

}
