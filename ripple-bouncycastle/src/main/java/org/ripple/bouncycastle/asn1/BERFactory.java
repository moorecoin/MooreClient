package org.ripple.bouncycastle.asn1;

class berfactory
{
    static final bersequence empty_sequence = new bersequence();
    static final berset empty_set = new berset();

    static bersequence createsequence(asn1encodablevector v)
    {
        return v.size() < 1 ? empty_sequence : new bersequence(v);
    }

    static berset createset(asn1encodablevector v)
    {
        return v.size() < 1 ? empty_set : new berset(v);
    }
}
