package org.ripple.bouncycastle.asn1.teletrust;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface teletrustobjectidentifiers
{
    static final asn1objectidentifier teletrustalgorithm = new asn1objectidentifier("1.3.36.3");

    static final asn1objectidentifier    ripemd160           = teletrustalgorithm.branch("2.1");
    static final asn1objectidentifier    ripemd128           = teletrustalgorithm.branch("2.2");
    static final asn1objectidentifier    ripemd256           = teletrustalgorithm.branch("2.3");

    static final asn1objectidentifier teletrustrsasignaturealgorithm = teletrustalgorithm.branch("3.1");

    static final asn1objectidentifier    rsasignaturewithripemd160           = teletrustrsasignaturealgorithm.branch("2");
    static final asn1objectidentifier    rsasignaturewithripemd128           = teletrustrsasignaturealgorithm.branch("3");
    static final asn1objectidentifier    rsasignaturewithripemd256           = teletrustrsasignaturealgorithm.branch("4");

    static final asn1objectidentifier    ecsign = teletrustalgorithm.branch("3.2");

    static final asn1objectidentifier    ecsignwithsha1  = ecsign.branch("1");
    static final asn1objectidentifier    ecsignwithripemd160  = ecsign.branch("2");

    static final asn1objectidentifier ecc_brainpool = teletrustalgorithm.branch("3.2.8");
    static final asn1objectidentifier ellipticcurve = ecc_brainpool.branch("1");
    static final asn1objectidentifier versionone = ellipticcurve.branch("1");

    static final asn1objectidentifier brainpoolp160r1 = versionone.branch("1");
    static final asn1objectidentifier brainpoolp160t1 = versionone.branch("2");
    static final asn1objectidentifier brainpoolp192r1 = versionone.branch("3");
    static final asn1objectidentifier brainpoolp192t1 = versionone.branch("4");
    static final asn1objectidentifier brainpoolp224r1 = versionone.branch("5");
    static final asn1objectidentifier brainpoolp224t1 = versionone.branch("6");
    static final asn1objectidentifier brainpoolp256r1 = versionone.branch("7");
    static final asn1objectidentifier brainpoolp256t1 = versionone.branch("8");
    static final asn1objectidentifier brainpoolp320r1 = versionone.branch("9");
    static final asn1objectidentifier brainpoolp320t1 = versionone.branch("10");
    static final asn1objectidentifier brainpoolp384r1 = versionone.branch("11");
    static final asn1objectidentifier brainpoolp384t1 = versionone.branch("12");
    static final asn1objectidentifier brainpoolp512r1 = versionone.branch("13");
    static final asn1objectidentifier brainpoolp512t1 = versionone.branch("14");
}
