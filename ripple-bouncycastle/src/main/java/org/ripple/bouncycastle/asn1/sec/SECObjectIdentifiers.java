package org.ripple.bouncycastle.asn1.sec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;

public interface secobjectidentifiers
{
    /**
     *  ellipticcurve object identifier ::= {
     *        iso(1) identified-organization(3) certicom(132) curve(0)
     *  }
     */
    static final asn1objectidentifier ellipticcurve = new asn1objectidentifier("1.3.132.0");

    static final asn1objectidentifier sect163k1 = ellipticcurve.branch("1");
    static final asn1objectidentifier sect163r1 = ellipticcurve.branch("2");
    static final asn1objectidentifier sect239k1 = ellipticcurve.branch("3");
    static final asn1objectidentifier sect113r1 = ellipticcurve.branch("4");
    static final asn1objectidentifier sect113r2 = ellipticcurve.branch("5");
    static final asn1objectidentifier secp112r1 = ellipticcurve.branch("6");
    static final asn1objectidentifier secp112r2 = ellipticcurve.branch("7");
    static final asn1objectidentifier secp160r1 = ellipticcurve.branch("8");
    static final asn1objectidentifier secp160k1 = ellipticcurve.branch("9");
    static final asn1objectidentifier secp256k1 = ellipticcurve.branch("10");
    static final asn1objectidentifier sect163r2 = ellipticcurve.branch("15");
    static final asn1objectidentifier sect283k1 = ellipticcurve.branch("16");
    static final asn1objectidentifier sect283r1 = ellipticcurve.branch("17");
    static final asn1objectidentifier sect131r1 = ellipticcurve.branch("22");
    static final asn1objectidentifier sect131r2 = ellipticcurve.branch("23");
    static final asn1objectidentifier sect193r1 = ellipticcurve.branch("24");
    static final asn1objectidentifier sect193r2 = ellipticcurve.branch("25");
    static final asn1objectidentifier sect233k1 = ellipticcurve.branch("26");
    static final asn1objectidentifier sect233r1 = ellipticcurve.branch("27");
    static final asn1objectidentifier secp128r1 = ellipticcurve.branch("28");
    static final asn1objectidentifier secp128r2 = ellipticcurve.branch("29");
    static final asn1objectidentifier secp160r2 = ellipticcurve.branch("30");
    static final asn1objectidentifier secp192k1 = ellipticcurve.branch("31");
    static final asn1objectidentifier secp224k1 = ellipticcurve.branch("32");
    static final asn1objectidentifier secp224r1 = ellipticcurve.branch("33");
    static final asn1objectidentifier secp384r1 = ellipticcurve.branch("34");
    static final asn1objectidentifier secp521r1 = ellipticcurve.branch("35");
    static final asn1objectidentifier sect409k1 = ellipticcurve.branch("36");
    static final asn1objectidentifier sect409r1 = ellipticcurve.branch("37");
    static final asn1objectidentifier sect571k1 = ellipticcurve.branch("38");
    static final asn1objectidentifier sect571r1 = ellipticcurve.branch("39");

    static final asn1objectidentifier secp192r1 = x9objectidentifiers.prime192v1;
    static final asn1objectidentifier secp256r1 = x9objectidentifiers.prime256v1;

}
