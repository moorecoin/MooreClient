package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface cmpobjectidentifiers
{
    // rfc 4210

    // id-passwordbasedmac object identifier ::= {1 2 840 113533 7 66 13}
    static final asn1objectidentifier    passwordbasedmac        = new asn1objectidentifier("1.2.840.113533.7.66.13");

    // id-dhbasedmac object identifier ::= {1 2 840 113533 7 66 30}
    static final asn1objectidentifier    dhbasedmac              = new asn1objectidentifier("1.2.840.113533.7.66.30");

    // example infotypeandvalue contents include, but are not limited
    // to, the following (un-comment in this asn.1 module and use as
    // appropriate for a given environment):
    //
    //   id-it-caprotenccert    object identifier ::= {id-it 1}
    //      caprotenccertvalue      ::= cmpcertificate
    //   id-it-signkeypairtypes object identifier ::= {id-it 2}
    //      signkeypairtypesvalue   ::= sequence of algorithmidentifier
    //   id-it-enckeypairtypes  object identifier ::= {id-it 3}
    //      enckeypairtypesvalue    ::= sequence of algorithmidentifier
    //   id-it-preferredsymmalg object identifier ::= {id-it 4}
    //      preferredsymmalgvalue   ::= algorithmidentifier
    //   id-it-cakeyupdateinfo  object identifier ::= {id-it 5}
    //      cakeyupdateinfovalue    ::= cakeyupdanncontent
    //   id-it-currentcrl       object identifier ::= {id-it 6}
    //      currentcrlvalue         ::= certificatelist
    //   id-it-unsupportedoids  object identifier ::= {id-it 7}
    //      unsupportedoidsvalue    ::= sequence of object identifier
    //   id-it-keypairparamreq  object identifier ::= {id-it 10}
    //      keypairparamreqvalue    ::= object identifier
    //   id-it-keypairparamrep  object identifier ::= {id-it 11}
    //      keypairparamrepvalue    ::= algorithmidentifer
    //   id-it-revpassphrase    object identifier ::= {id-it 12}
    //      revpassphrasevalue      ::= encryptedvalue
    //   id-it-implicitconfirm  object identifier ::= {id-it 13}
    //      implicitconfirmvalue    ::= null
    //   id-it-confirmwaittime  object identifier ::= {id-it 14}
    //      confirmwaittimevalue    ::= generalizedtime
    //   id-it-origpkimessage   object identifier ::= {id-it 15}
    //      origpkimessagevalue     ::= pkimessages
    //   id-it-supplangtags     object identifier ::= {id-it 16}
    //      supplangtagsvalue       ::= sequence of utf8string
    //
    // where
    //
    //   id-pkix object identifier ::= {
    //      iso(1) identified-organization(3)
    //      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
    // and
    //   id-it   object identifier ::= {id-pkix 4}
    static final asn1objectidentifier    it_caprotenccert        = new asn1objectidentifier("1.3.6.1.5.5.7.4.1");
    static final asn1objectidentifier    it_signkeypairtypes     = new asn1objectidentifier("1.3.6.1.5.5.7.4.2");
    static final asn1objectidentifier    it_enckeypairtypes      = new asn1objectidentifier("1.3.6.1.5.5.7.4.3");
    static final asn1objectidentifier    it_preferredsymalg      = new asn1objectidentifier("1.3.6.1.5.5.7.4.4");
    static final asn1objectidentifier    it_cakeyupdateinfo      = new asn1objectidentifier("1.3.6.1.5.5.7.4.5");
    static final asn1objectidentifier    it_currentcrl           = new asn1objectidentifier("1.3.6.1.5.5.7.4.6");
    static final asn1objectidentifier    it_unsupportedoids      = new asn1objectidentifier("1.3.6.1.5.5.7.4.7");
    static final asn1objectidentifier    it_keypairparamreq      = new asn1objectidentifier("1.3.6.1.5.5.7.4.10");
    static final asn1objectidentifier    it_keypairparamrep      = new asn1objectidentifier("1.3.6.1.5.5.7.4.11");
    static final asn1objectidentifier    it_revpassphrase        = new asn1objectidentifier("1.3.6.1.5.5.7.4.12");
    static final asn1objectidentifier    it_implicitconfirm      = new asn1objectidentifier("1.3.6.1.5.5.7.4.13");
    static final asn1objectidentifier    it_confirmwaittime      = new asn1objectidentifier("1.3.6.1.5.5.7.4.14");
    static final asn1objectidentifier    it_origpkimessage       = new asn1objectidentifier("1.3.6.1.5.5.7.4.15");
    static final asn1objectidentifier    it_supplangtags         = new asn1objectidentifier("1.3.6.1.5.5.7.4.16");

    // rfc 4211

    // id-pkix  object identifier  ::= { iso(1) identified-organization(3)
    //     dod(6) internet(1) security(5) mechanisms(5) pkix(7) }
    //
    // arc for internet x.509 pki protocols and their components
    // id-pkip  object identifier :: { id-pkix pkip(5) }
    //
    // arc for registration controls in crmf
    // id-regctrl  object identifier ::= { id-pkip regctrl(1) }
    //
    // arc for registration info in crmf
    // id-reginfo       object identifier ::= { id-pkip id-reginfo(2) }

    static final asn1objectidentifier    regctrl_regtoken        = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.1");
    static final asn1objectidentifier    regctrl_authenticator   = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.2");
    static final asn1objectidentifier    regctrl_pkipublicationinfo = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.3");
    static final asn1objectidentifier    regctrl_pkiarchiveoptions  = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.4");
    static final asn1objectidentifier    regctrl_oldcertid       = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.5");
    static final asn1objectidentifier    regctrl_protocolencrkey = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.6");

    // from rfc4210:
    // id-regctrl-altcerttemplate object identifier ::= {id-regctrl 7}
    static final asn1objectidentifier    regctrl_altcerttemplate = new asn1objectidentifier("1.3.6.1.5.5.7.5.1.7");

    static final asn1objectidentifier    reginfo_utf8pairs       = new asn1objectidentifier("1.3.6.1.5.5.7.5.2.1");
    static final asn1objectidentifier    reginfo_certreq         = new asn1objectidentifier("1.3.6.1.5.5.7.5.2.2");

    // id-smime object identifier ::= { iso(1) member-body(2)
    //         us(840) rsadsi(113549) pkcs(1) pkcs9(9) 16 }
    //
    // id-ct   object identifier ::= { id-smime  1 }  -- content types
    //
    // id-ct-enckeywithid object identifier ::= {id-ct 21}
    static final asn1objectidentifier    ct_enckeywithid         = new asn1objectidentifier("1.2.840.113549.1.9.16.1.21");

}
