package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class nameconstraints
    extends asn1object
{
    private generalsubtree[] permitted, excluded;

    public static nameconstraints getinstance(object obj)
    {
        if (obj instanceof nameconstraints)
        {
            return (nameconstraints)obj;
        }
        if (obj != null)
        {
            return new nameconstraints(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private nameconstraints(asn1sequence seq)
    {
        enumeration e = seq.getobjects();
        while (e.hasmoreelements())
        {
            asn1taggedobject o = asn1taggedobject.getinstance(e.nextelement());
            switch (o.gettagno())
            {
                case 0:
                    permitted = createarray(asn1sequence.getinstance(o, false));
                    break;
                case 1:
                    excluded = createarray(asn1sequence.getinstance(o, false));
                    break;
            }
        }
    }

    /**
     * constructor from a given details.
     * 
     * <p>
     * permitted and excluded are arrays of generalsubtree objects.
     * 
     * @param permitted
     *            permitted subtrees
     * @param excluded
     *            excludes subtrees
     */
    public nameconstraints(
        generalsubtree[] permitted,
        generalsubtree[] excluded)
    {
        if (permitted != null)
        {
            this.permitted = permitted;
        }

        if (excluded != null)
        {
            this.excluded = excluded;
        }
    }

    private generalsubtree[] createarray(asn1sequence subtree)
    {
        generalsubtree[] ar = new generalsubtree[subtree.size()];

        for (int i = 0; i != ar.length; i++)
        {
            ar[i] = generalsubtree.getinstance(subtree.getobjectat(i));
        }

        return ar;
    }

    public generalsubtree[] getpermittedsubtrees()
    {
        return permitted;
    }

    public generalsubtree[] getexcludedsubtrees()
    {
        return excluded;
    }

    /*
     * nameconstraints ::= sequence { permittedsubtrees [0] generalsubtrees
     * optional, excludedsubtrees [1] generalsubtrees optional }
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (permitted != null)
        {
            v.add(new dertaggedobject(false, 0, new dersequence(permitted)));
        }

        if (excluded != null)
        {
            v.add(new dertaggedobject(false, 1, new dersequence(excluded)));
        }

        return new dersequence(v);
    }
}
