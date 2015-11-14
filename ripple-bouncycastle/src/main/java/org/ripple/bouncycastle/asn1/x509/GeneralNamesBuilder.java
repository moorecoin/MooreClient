package org.ripple.bouncycastle.asn1.x509;

import java.util.vector;

public class generalnamesbuilder
{
    private vector names = new vector();

    public generalnamesbuilder addnames(generalnames names)
    {
        generalname[] n = names.getnames();

        for (int i = 0; i != n.length; i++)
        {
            this.names.addelement(n[i]);
        }

        return this;
    }

    public generalnamesbuilder addname(generalname name)
    {
        names.addelement(name);

        return this;
    }

    public generalnames build()
    {
        generalname[] tmp = new generalname[names.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (generalname)names.elementat(i);
        }

        return new generalnames(tmp);
    }
}
