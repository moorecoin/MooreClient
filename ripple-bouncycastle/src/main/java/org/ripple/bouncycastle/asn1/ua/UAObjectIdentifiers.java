package org.ripple.bouncycastle.asn1.ua;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface uaobjectidentifiers
{
    // ukrainian object identifiers
    // {iso(1) member-body(2) ukraine(804 ) root(2) security(1) cryptography(1) pki(1)}

    static final asn1objectidentifier uaoid = new asn1objectidentifier("1.2.804.2.1.1.1");

    // {pki-alg(1) pki-alg-锟絪ym(3) dstu4145withgost34311(1) pb(1)}
    // dstu4145 in polynomial basis has 2 oids, one for little-endian representation and one for big-endian
    static final asn1objectidentifier dstu4145le = uaoid.branch("1.3.1.1");
    static final asn1objectidentifier dstu4145be = uaoid.branch("1.3.1.1.1.1");
}
