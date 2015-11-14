package org.ripple.bouncycastle.asn1;

class derfactory
{
    static final asn1sequence empty_sequence = new dersequence();
    static final asn1set empty_set = new derset();

    static asn1sequence createsequence(asn1encodablevector v)
    {
        return v.size() < 1 ? empty_sequence : new dlsequence(v);
    }

    static asn1set createset(asn1encodablevector v)
    {
        return v.size() < 1 ? empty_set : new dlset(v);
    }
}
