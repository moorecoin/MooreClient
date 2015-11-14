package org.ripple.bouncycastle.asn1;

import java.util.enumeration;
import java.util.vector;

public class asn1encodablevector
{
    vector v = new vector();

    public asn1encodablevector()
    {
    }

    public void add(asn1encodable obj)
    {
        v.addelement(obj);
    }

    public void addall(asn1encodablevector other)
    {
        for (enumeration en = other.v.elements(); en.hasmoreelements();)
        {
            v.addelement(en.nextelement());
        }
    }

    public asn1encodable get(int i)
    {
        return (asn1encodable)v.elementat(i);
    }

    public int size()
    {
        return v.size();
    }
}
