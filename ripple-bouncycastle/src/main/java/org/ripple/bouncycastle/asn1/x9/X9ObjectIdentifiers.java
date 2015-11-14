package org.ripple.bouncycastle.asn1.x9;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface x9objectidentifiers
{
    //
    // x9.62
    //
    // ansi-x9-62 object identifier ::= { iso(1) member-body(2)
    //            us(840) ansi-x962(10045) }
    //
    static final asn1objectidentifier ansi_x9_62 = new asn1objectidentifier("1.2.840.10045");
    static final asn1objectidentifier id_fieldtype = ansi_x9_62.branch("1");

    static final asn1objectidentifier prime_field = id_fieldtype.branch("1");

    static final asn1objectidentifier characteristic_two_field = id_fieldtype.branch("2");

    static final asn1objectidentifier gnbasis = characteristic_two_field.branch("3.1");

    static final asn1objectidentifier tpbasis = characteristic_two_field.branch("3.2");

    static final asn1objectidentifier ppbasis = characteristic_two_field.branch("3.3");

    static final asn1objectidentifier id_ecsigtype = ansi_x9_62.branch("4");

    static final asn1objectidentifier ecdsa_with_sha1 = new asn1objectidentifier(id_ecsigtype + ".1");

    static final asn1objectidentifier id_publickeytype = ansi_x9_62.branch("2");

    static final asn1objectidentifier id_ecpublickey = id_publickeytype.branch("1");

    static final asn1objectidentifier ecdsa_with_sha2 = id_ecsigtype.branch("3");

    static final asn1objectidentifier ecdsa_with_sha224 = ecdsa_with_sha2.branch("1");

    static final asn1objectidentifier ecdsa_with_sha256 = ecdsa_with_sha2.branch("2");

    static final asn1objectidentifier ecdsa_with_sha384 = ecdsa_with_sha2.branch("3");

    static final asn1objectidentifier ecdsa_with_sha512 = ecdsa_with_sha2.branch("4");

    //
    // named curves
    //
    static final asn1objectidentifier ellipticcurve = ansi_x9_62.branch("3");

    //
    // two curves
    //
    static final asn1objectidentifier  ctwocurve = ellipticcurve.branch("0");

    static final asn1objectidentifier c2pnb163v1 = ctwocurve.branch("1");
    static final asn1objectidentifier c2pnb163v2 = ctwocurve.branch("2");
    static final asn1objectidentifier c2pnb163v3 = ctwocurve.branch("3");
    static final asn1objectidentifier c2pnb176w1 = ctwocurve.branch("4");
    static final asn1objectidentifier c2tnb191v1 = ctwocurve.branch("5");
    static final asn1objectidentifier c2tnb191v2 = ctwocurve.branch("6");
    static final asn1objectidentifier c2tnb191v3 = ctwocurve.branch("7");
    static final asn1objectidentifier c2onb191v4 = ctwocurve.branch("8");
    static final asn1objectidentifier c2onb191v5 = ctwocurve.branch("9");
    static final asn1objectidentifier c2pnb208w1 = ctwocurve.branch("10");
    static final asn1objectidentifier c2tnb239v1 = ctwocurve.branch("11");
    static final asn1objectidentifier c2tnb239v2 = ctwocurve.branch("12");
    static final asn1objectidentifier c2tnb239v3 = ctwocurve.branch("13");
    static final asn1objectidentifier c2onb239v4 = ctwocurve.branch("14");
    static final asn1objectidentifier c2onb239v5 = ctwocurve.branch("15");
    static final asn1objectidentifier c2pnb272w1 = ctwocurve.branch("16");
    static final asn1objectidentifier c2pnb304w1 = ctwocurve.branch("17");
    static final asn1objectidentifier c2tnb359v1 = ctwocurve.branch("18");
    static final asn1objectidentifier c2pnb368w1 = ctwocurve.branch("19");
    static final asn1objectidentifier c2tnb431r1 = ctwocurve.branch("20");

    //
    // prime
    //
    static final asn1objectidentifier primecurve = ellipticcurve.branch("1");

    static final asn1objectidentifier prime192v1 = primecurve.branch("1");
    static final asn1objectidentifier prime192v2 = primecurve.branch("2");
    static final asn1objectidentifier prime192v3 = primecurve.branch("3");
    static final asn1objectidentifier prime239v1 = primecurve.branch("4");
    static final asn1objectidentifier prime239v2 = primecurve.branch("5");
    static final asn1objectidentifier prime239v3 = primecurve.branch("6");
    static final asn1objectidentifier prime256v1 = primecurve.branch("7");

    //
    // dsa
    //
    // dsapublicnumber object identifier ::= { iso(1) member-body(2)
    //            us(840) ansi-x957(10040) number-type(4) 1 }
    static final asn1objectidentifier id_dsa = new asn1objectidentifier("1.2.840.10040.4.1");

    /**
     * id-dsa-with-sha1 object identifier ::= { iso(1) member-body(2) us(840) x9-57
     * (10040) x9cm(4) 3 }
     */
    public static final asn1objectidentifier id_dsa_with_sha1 = new asn1objectidentifier("1.2.840.10040.4.3");

    /**
     * x9.63
     */
    public static final asn1objectidentifier x9_63_scheme = new asn1objectidentifier("1.3.133.16.840.63.0");
    public static final asn1objectidentifier dhsinglepass_stddh_sha1kdf_scheme = x9_63_scheme.branch("2");
    public static final asn1objectidentifier dhsinglepass_cofactordh_sha1kdf_scheme = x9_63_scheme.branch("3");
    public static final asn1objectidentifier mqvsinglepass_sha1kdf_scheme = x9_63_scheme.branch("16");

    /**
     * x9.42
     */

    static final asn1objectidentifier ansi_x9_42 = new asn1objectidentifier("1.2.840.10046");

    //
    // diffie-hellman
    //
    // dhpublicnumber object identifier ::= { iso(1) member-body(2)
    //            us(840) ansi-x942(10046) number-type(2) 1 }
    //
    public static final asn1objectidentifier dhpublicnumber = ansi_x9_42.branch("2.1");

    public static final asn1objectidentifier x9_42_schemes = ansi_x9_42.branch("3");
    public static final asn1objectidentifier dhstatic = x9_42_schemes.branch("1");
    public static final asn1objectidentifier dhephem = x9_42_schemes.branch("2");
    public static final asn1objectidentifier dhoneflow = x9_42_schemes.branch("3");
    public static final asn1objectidentifier dhhybrid1 = x9_42_schemes.branch("4");
    public static final asn1objectidentifier dhhybrid2 = x9_42_schemes.branch("5");
    public static final asn1objectidentifier dhhybridoneflow = x9_42_schemes.branch("6");
    public static final asn1objectidentifier mqv2 = x9_42_schemes.branch("7");
    public static final asn1objectidentifier mqv1 = x9_42_schemes.branch("8");
}
