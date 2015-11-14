package org.ripple.bouncycastle.asn1.x500;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.style.bcstyle;

/**
 * <pre>
 *     name ::= choice {
 *                       rdnsequence }
 *
 *     rdnsequence ::= sequence of relativedistinguishedname
 *
 *     relativedistinguishedname ::= set size (1..max) of attributetypeandvalue
 *
 *     attributetypeandvalue ::= sequence {
 *                                   type  object identifier,
 *                                   value any }
 * </pre>
 */
public class x500name
    extends asn1object
    implements asn1choice
{
    private static x500namestyle    defaultstyle = bcstyle.instance;

    private boolean                 ishashcodecalculated;
    private int                     hashcodevalue;

    private x500namestyle style;
    private rdn[] rdns;

    public x500name(x500namestyle style, x500name name)
    {
        this.rdns = name.rdns;
        this.style = style;
    }

    /**
     * return a x500name based on the passed in tagged object.
     * 
     * @param obj tag object holding name.
     * @param explicit true if explicitly tagged false otherwise.
     * @return the x500name
     */
    public static x500name getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        // must be true as choice item
        return getinstance(asn1sequence.getinstance(obj, true));
    }

    public static x500name getinstance(
        object  obj)
    {
        if (obj instanceof x500name)
        {
            return (x500name)obj;
        }
        else if (obj != null)
        {
            return new x500name(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static x500name getinstance(
        x500namestyle style,
        object        obj)
    {
        if (obj instanceof x500name)
        {
            return getinstance(style, ((x500name)obj).toasn1primitive());
        }
        else if (obj != null)
        {
            return new x500name(style, asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from asn1sequence
     *
     * the principal will be a list of constructed sets, each containing an (oid, string) pair.
     */
    private x500name(
        asn1sequence  seq)
    {
        this(defaultstyle, seq);
    }

    private x500name(
        x500namestyle style,
        asn1sequence  seq)
    {
        this.style = style;
        this.rdns = new rdn[seq.size()];

        int index = 0;

        for (enumeration e = seq.getobjects(); e.hasmoreelements();)
        {
            rdns[index++] = rdn.getinstance(e.nextelement());
        }
    }

    public x500name(
        rdn[] rdns)
    {
        this(defaultstyle, rdns);
    }

    public x500name(
        x500namestyle style,
        rdn[]         rdns)
    {
        this.rdns = rdns;
        this.style = style;
    }

    public x500name(
        string dirname)
    {
        this(defaultstyle, dirname);
    }

    public x500name(
        x500namestyle style,
        string        dirname)
    {
        this(style.fromstring(dirname));

        this.style = style;
    }

    /**
     * return an array of rdns in structure order.
     *
     * @return an array of rdn objects.
     */
    public rdn[] getrdns()
    {
        rdn[] tmp = new rdn[this.rdns.length];

        system.arraycopy(rdns, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * return an array of oids contained in the attribute type of each rdn in structure order.
     *
     * @return an array, possibly zero length, of asn1objectidentifiers objects.
     */
    public asn1objectidentifier[] getattributetypes()
    {
        int   count = 0;

        for (int i = 0; i != rdns.length; i++)
        {
            rdn rdn = rdns[i];

            count += rdn.size();
        }

        asn1objectidentifier[] res = new asn1objectidentifier[count];

        count = 0;

        for (int i = 0; i != rdns.length; i++)
        {
            rdn rdn = rdns[i];

            if (rdn.ismultivalued())
            {
                attributetypeandvalue[] attr = rdn.gettypesandvalues();
                for (int j = 0; j != attr.length; j++)
                {
                    res[count++] = attr[j].gettype();
                }
            }
            else if (rdn.size() != 0)
            {
                res[count++] = rdn.getfirst().gettype();
            }
        }

        return res;
    }

    /**
     * return an array of rdns containing the attribute type given by oid in structure order.
     *
     * @param attributetype the type oid we are looking for.
     * @return an array, possibly zero length, of rdn objects.
     */
    public rdn[] getrdns(asn1objectidentifier attributetype)
    {
        rdn[] res = new rdn[rdns.length];
        int   count = 0;

        for (int i = 0; i != rdns.length; i++)
        {
            rdn rdn = rdns[i];

            if (rdn.ismultivalued())
            {
                attributetypeandvalue[] attr = rdn.gettypesandvalues();
                for (int j = 0; j != attr.length; j++)
                {
                    if (attr[j].gettype().equals(attributetype))
                    {
                        res[count++] = rdn;
                        break;
                    }
                }
            }
            else
            {
                if (rdn.getfirst().gettype().equals(attributetype))
                {
                    res[count++] = rdn;
                }
            }
        }

        rdn[] tmp = new rdn[count];

        system.arraycopy(res, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public asn1primitive toasn1primitive()
    {
        return new dersequence(rdns);
    }

    public int hashcode()
    {
        if (ishashcodecalculated)
        {
            return hashcodevalue;
        }

        ishashcodecalculated = true;

        hashcodevalue = style.calculatehashcode(this);

        return hashcodevalue;
    }

    /**
     * test for equality - note: case is ignored.
     */
    public boolean equals(object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof x500name || obj instanceof asn1sequence))
        {
            return false;
        }
        
        asn1primitive dero = ((asn1encodable)obj).toasn1primitive();

        if (this.toasn1primitive().equals(dero))
        {
            return true;
        }

        try
        {
            return style.areequal(this, new x500name(asn1sequence.getinstance(((asn1encodable)obj).toasn1primitive())));
        }
        catch (exception e)
        {
            return false;
        }
    }
    
    public string tostring()
    {
        return style.tostring(this);
    }

    /**
     * set the default style for x500name construction.
     *
     * @param style  an x500namestyle
     */
    public static void setdefaultstyle(x500namestyle style)
    {
        if (style == null)
        {
            throw new nullpointerexception("cannot set style to null");
        }

        defaultstyle = style;
    }

    /**
     * return the current default style.
     *
     * @return default style for x500name construction.
     */
    public static x500namestyle getdefaultstyle()
    {
        return defaultstyle;
    }
}
