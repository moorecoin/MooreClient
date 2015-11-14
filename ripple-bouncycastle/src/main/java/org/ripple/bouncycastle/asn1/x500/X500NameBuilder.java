package org.ripple.bouncycastle.asn1.x500;

import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.x500.style.bcstyle;

public class x500namebuilder
{
    private x500namestyle template;
    private vector rdns = new vector();

    public x500namebuilder()
    {
        this(bcstyle.instance);
    }

    public x500namebuilder(x500namestyle template)
    {
        this.template = template;
    }

    public x500namebuilder addrdn(asn1objectidentifier oid, string value)
    {
        this.addrdn(oid, template.stringtovalue(oid, value));

        return this;
    }

    public x500namebuilder addrdn(asn1objectidentifier oid, asn1encodable value)
    {
        rdns.addelement(new rdn(oid, value));

        return this;
    }

    public x500namebuilder addrdn(attributetypeandvalue attrtandv)
    {
        rdns.addelement(new rdn(attrtandv));

        return this;
    }

    public x500namebuilder addmultivaluedrdn(asn1objectidentifier[] oids, string[] values)
    {
        asn1encodable[] vals = new asn1encodable[values.length];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = template.stringtovalue(oids[i], values[i]);
        }

        return addmultivaluedrdn(oids, vals);
    }

    public x500namebuilder addmultivaluedrdn(asn1objectidentifier[] oids, asn1encodable[] values)
    {
        attributetypeandvalue[] avs = new attributetypeandvalue[oids.length];

        for (int i = 0; i != oids.length; i++)
        {
            avs[i] = new attributetypeandvalue(oids[i], values[i]);
        }

        return addmultivaluedrdn(avs);
    }

    public x500namebuilder addmultivaluedrdn(attributetypeandvalue[] attrtandvs)
    {
        rdns.addelement(new rdn(attrtandvs));

        return this;
    }

    public x500name build()
    {
        rdn[] vals = new rdn[rdns.size()];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = (rdn)rdns.elementat(i);
        }

        return new x500name(template, vals);
    }
}
