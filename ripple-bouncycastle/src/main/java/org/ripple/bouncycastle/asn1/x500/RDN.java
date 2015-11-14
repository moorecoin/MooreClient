package org.ripple.bouncycastle.asn1.x500;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;

public class rdn
    extends asn1object
{
    private asn1set values;

    private rdn(asn1set values)
    {
        this.values = values;
    }

    public static rdn getinstance(object obj)
    {
        if (obj instanceof rdn)
        {
            return (rdn)obj;
        }
        else if (obj != null)
        {
            return new rdn(asn1set.getinstance(obj));
        }

        return null;
    }

    /**
     * create a single valued rdn.
     *
     * @param oid rdn type.
     * @param value rdn value.
     */
    public rdn(asn1objectidentifier oid, asn1encodable value)
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(oid);
        v.add(value);

        this.values = new derset(new dersequence(v));
    }

    public rdn(attributetypeandvalue attrtandv)
    {
        this.values = new derset(attrtandv);
    }

    /**
     * create a multi-valued rdn.
     *
     * @param aandvs attribute type/value pairs making up the rdn
     */
    public rdn(attributetypeandvalue[] aandvs)
    {
        this.values = new derset(aandvs);
    }

    public boolean ismultivalued()
    {
        return this.values.size() > 1;
    }

    /**
     * return the number of attributetypeandvalue objects in this rdn,
     *
     * @return size of rdn, greater than 1 if multi-valued.
     */
    public int size()
    {
        return this.values.size();
    }

    public attributetypeandvalue getfirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return attributetypeandvalue.getinstance(this.values.getobjectat(0));
    }

    public attributetypeandvalue[] gettypesandvalues()
    {
        attributetypeandvalue[] tmp = new attributetypeandvalue[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = attributetypeandvalue.getinstance(values.getobjectat(i));
        }

        return tmp;
    }

    /**
     * <pre>
     * relativedistinguishedname ::=
     *                     set of attributetypeandvalue

     * attributetypeandvalue ::= sequence {
     *        type     attributetype,
     *        value    attributevalue }
     * </pre>
     * @return this object as an asn1primitive type
     */
    public asn1primitive toasn1primitive()
    {
        return values;
    }
}
