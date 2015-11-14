package org.ripple.bouncycastle.pqc.asn1;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface pqcobjectidentifiers
{
    public static final asn1objectidentifier rainbow = new asn1objectidentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");

    public static final asn1objectidentifier rainbowwithsha1 = rainbow.branch("1");
    public static final asn1objectidentifier rainbowwithsha224 = rainbow.branch("2");
    public static final asn1objectidentifier rainbowwithsha256 = rainbow.branch("3");
    public static final asn1objectidentifier rainbowwithsha384 = rainbow.branch("4");
    public static final asn1objectidentifier rainbowwithsha512 = rainbow.branch("5");

    public static final asn1objectidentifier gmss = new asn1objectidentifier("1.3.6.1.4.1.8301.3.1.3.3");

    public static final asn1objectidentifier gmsswithsha1 = gmss.branch("1");
    public static final asn1objectidentifier gmsswithsha224 = gmss.branch("2");
    public static final asn1objectidentifier gmsswithsha256 = gmss.branch("3");
    public static final asn1objectidentifier gmsswithsha384 = gmss.branch("4");
    public static final asn1objectidentifier gmsswithsha512 = gmss.branch("5");

    public static final asn1objectidentifier mceliece = new asn1objectidentifier("1.3.6.1.4.1.8301.3.1.3.4.1");

    public static final asn1objectidentifier mceliececca2 = new asn1objectidentifier("1.3.6.1.4.1.8301.3.1.3.4.2");

}
