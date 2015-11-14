package org.ripple.bouncycastle.asn1.cryptopro;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface cryptoproobjectidentifiers
{
    // gost algorithms object identifiers :
    // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)}
    static final asn1objectidentifier    gost_id              = new asn1objectidentifier("1.2.643.2.2");

    static final asn1objectidentifier    gostr3411          = gost_id.branch("9");
    static final asn1objectidentifier    gostr3411hmac      = gost_id.branch("10");

    static final asn1objectidentifier    gostr28147_cbc     = new asn1objectidentifier(gost_id+".21");

    static final asn1objectidentifier    id_gost28147_89_cryptopro_a_paramset = gost_id.branch("31.1");

    static final asn1objectidentifier    gostr3410_94       = new asn1objectidentifier(gost_id+".20");
    static final asn1objectidentifier    gostr3410_2001     = new asn1objectidentifier(gost_id+".19");
    static final asn1objectidentifier    gostr3411_94_with_gostr3410_94   = new asn1objectidentifier(gost_id+".4");
    static final asn1objectidentifier    gostr3411_94_with_gostr3410_2001 = new asn1objectidentifier(gost_id+".3");

    // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) hashes(30) }
    static final asn1objectidentifier    gostr3411_94_cryptoproparamset = new asn1objectidentifier(gost_id+".30.1");

    // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) signs(32) }
    static final asn1objectidentifier    gostr3410_94_cryptopro_a     = new asn1objectidentifier(gost_id+".32.2");
    static final asn1objectidentifier    gostr3410_94_cryptopro_b     = new asn1objectidentifier(gost_id+".32.3");
    static final asn1objectidentifier    gostr3410_94_cryptopro_c     = new asn1objectidentifier(gost_id+".32.4");
    static final asn1objectidentifier    gostr3410_94_cryptopro_d     = new asn1objectidentifier(gost_id+".32.5");

    // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) exchanges(33) }
    static final asn1objectidentifier    gostr3410_94_cryptopro_xcha  = new asn1objectidentifier(gost_id+".33.1");
    static final asn1objectidentifier    gostr3410_94_cryptopro_xchb  = new asn1objectidentifier(gost_id+".33.2");
    static final asn1objectidentifier    gostr3410_94_cryptopro_xchc  = new asn1objectidentifier(gost_id+".33.3");

    //{ iso(1) member-body(2)ru(643) rans(2) cryptopro(2) ecc-signs(35) }
    static final asn1objectidentifier    gostr3410_2001_cryptopro_a = new asn1objectidentifier(gost_id+".35.1");
    static final asn1objectidentifier    gostr3410_2001_cryptopro_b = new asn1objectidentifier(gost_id+".35.2");
    static final asn1objectidentifier    gostr3410_2001_cryptopro_c = new asn1objectidentifier(gost_id+".35.3");

    // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) ecc-exchanges(36) }
    static final asn1objectidentifier    gostr3410_2001_cryptopro_xcha  = new asn1objectidentifier(gost_id+".36.0");
    static final asn1objectidentifier    gostr3410_2001_cryptopro_xchb  = new asn1objectidentifier(gost_id+".36.1");
    
    static final asn1objectidentifier    gost_elsgdh3410_default    = new asn1objectidentifier(gost_id+".36.0");
    static final asn1objectidentifier    gost_elsgdh3410_1          = new asn1objectidentifier(gost_id+".36.1");
}
