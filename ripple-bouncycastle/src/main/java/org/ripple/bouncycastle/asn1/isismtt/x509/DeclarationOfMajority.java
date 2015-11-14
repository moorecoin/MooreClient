package org.ripple.bouncycastle.asn1.isismtt.x509;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * a declaration of majority.
 * <p/>
 * <pre>
 *           declarationofmajoritysyntax ::= choice
 *           {
 *             notyoungerthan [0] implicit integer,
 *             fullageatcountry [1] implicit sequence
 *             {
 *               fullage boolean default true,
 *               country printablestring (size(2))
 *             }
 *             dateofbirth [2] implicit generalizedtime
 *           }
 * </pre>
 * <p/>
 * fullageatcountry indicates the majority of the owner with respect to the laws
 * of a specific country.
 */
public class declarationofmajority
    extends asn1object
    implements asn1choice
{
    public static final int notyoungerthan = 0;
    public static final int fullageatcountry = 1;
    public static final int dateofbirth = 2;

    private asn1taggedobject declaration;

    public declarationofmajority(int notyoungerthan)
    {
        declaration = new dertaggedobject(false, 0, new asn1integer(notyoungerthan));
    }

    public declarationofmajority(boolean fullage, string country)
    {
        if (country.length() > 2)
        {
            throw new illegalargumentexception("country can only be 2 characters");
        }

        if (fullage)
        {
            declaration = new dertaggedobject(false, 1, new dersequence(new derprintablestring(country, true)));
        }
        else
        {
            asn1encodablevector v = new asn1encodablevector();

            v.add(asn1boolean.false);
            v.add(new derprintablestring(country, true));

            declaration = new dertaggedobject(false, 1, new dersequence(v));
        }
    }

    public declarationofmajority(asn1generalizedtime dateofbirth)
    {
        declaration = new dertaggedobject(false, 2, dateofbirth);
    }

    public static declarationofmajority getinstance(object obj)
    {
        if (obj == null || obj instanceof declarationofmajority)
        {
            return (declarationofmajority)obj;
        }

        if (obj instanceof asn1taggedobject)
        {
            return new declarationofmajority((asn1taggedobject)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    private declarationofmajority(asn1taggedobject o)
    {
        if (o.gettagno() > 2)
        {
                throw new illegalargumentexception("bad tag number: " + o.gettagno());
        }
        declaration = o;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *           declarationofmajoritysyntax ::= choice
     *           {
     *             notyoungerthan [0] implicit integer,
     *             fullageatcountry [1] implicit sequence
     *             {
     *               fullage boolean default true,
     *               country printablestring (size(2))
     *             }
     *             dateofbirth [2] implicit generalizedtime
     *           }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        return declaration;
    }

    public int gettype()
    {
        return declaration.gettagno();
    }

    /**
     * @return notyoungerthan if that's what we are, -1 otherwise
     */
    public int notyoungerthan()
    {
        if (declaration.gettagno() != 0)
        {
            return -1;
        }

        return asn1integer.getinstance(declaration, false).getvalue().intvalue();
    }

    public asn1sequence fullageatcountry()
    {
        if (declaration.gettagno() != 1)
        {
            return null;
        }

        return asn1sequence.getinstance(declaration, false);
    }

    public asn1generalizedtime getdateofbirth()
    {
        if (declaration.gettagno() != 2)
        {
            return null;
        }

        return asn1generalizedtime.getinstance(declaration, false);
    }
}
