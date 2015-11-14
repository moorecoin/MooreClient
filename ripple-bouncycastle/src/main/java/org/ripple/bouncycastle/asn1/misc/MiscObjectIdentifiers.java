package org.ripple.bouncycastle.asn1.misc;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface miscobjectidentifiers
{
    //
    // netscape
    //       iso/itu(2) joint-assign(16) us(840) uscompany(1) netscape(113730) cert-extensions(1) }
    //
    static final asn1objectidentifier    netscape                = new asn1objectidentifier("2.16.840.1.113730.1");
    static final asn1objectidentifier    netscapecerttype        = netscape.branch("1");
    static final asn1objectidentifier    netscapebaseurl         = netscape.branch("2");
    static final asn1objectidentifier    netscaperevocationurl   = netscape.branch("3");
    static final asn1objectidentifier    netscapecarevocationurl = netscape.branch("4");
    static final asn1objectidentifier    netscaperenewalurl      = netscape.branch("7");
    static final asn1objectidentifier    netscapecapolicyurl     = netscape.branch("8");
    static final asn1objectidentifier    netscapesslservername   = netscape.branch("12");
    static final asn1objectidentifier    netscapecertcomment     = netscape.branch("13");
    
    //
    // verisign
    //       iso/itu(2) joint-assign(16) us(840) uscompany(1) verisign(113733) cert-extensions(1) }
    //
    static final asn1objectidentifier   verisign                = new asn1objectidentifier("2.16.840.1.113733.1");

    //
    // czag - country, zip, age, and gender
    //
    static final asn1objectidentifier    verisignczagextension   = verisign.branch("6.3");
    // d&b d-u-n-s number
    static final asn1objectidentifier    verisigndnbdunsnumber   = verisign.branch("6.15");

    //
    // novell
    //       iso/itu(2) country(16) us(840) organization(1) novell(113719)
    //
    static final asn1objectidentifier    novell                  = new asn1objectidentifier("2.16.840.1.113719");
    static final asn1objectidentifier    novellsecurityattribs   = novell.branch("1.9.4.1");

    //
    // entrust
    //       iso(1) member-body(16) us(840) nortelnetworks(113533) entrust(7)
    //
    static final asn1objectidentifier    entrust                 = new asn1objectidentifier("1.2.840.113533.7");
    static final asn1objectidentifier    entrustversionextension = entrust.branch("65.0");
}
