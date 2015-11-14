package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derboolean;
import org.ripple.bouncycastle.asn1.dersequence;

public class basicconstraints
    extends asn1object
{
    asn1boolean  ca = asn1boolean.getinstance(false);
    asn1integer  pathlenconstraint = null;

    public static basicconstraints getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static basicconstraints getinstance(
        object  obj)
    {
        if (obj instanceof basicconstraints)
        {
            return (basicconstraints)obj;
        }
        if (obj instanceof x509extension)
        {
            return getinstance(x509extension.convertvaluetoobject((x509extension)obj));
        }
        if (obj != null)
        {
            return new basicconstraints(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static basicconstraints fromextensions(extensions extensions)
    {
        return basicconstraints.getinstance(extensions.getextensionparsedvalue(extension.basicconstraints));
    }

    private basicconstraints(
        asn1sequence   seq)
    {
        if (seq.size() == 0)
        {
            this.ca = null;
            this.pathlenconstraint = null;
        }
        else
        {
            if (seq.getobjectat(0) instanceof derboolean)
            {
                this.ca = derboolean.getinstance(seq.getobjectat(0));
            }
            else
            {
                this.ca = null;
                this.pathlenconstraint = asn1integer.getinstance(seq.getobjectat(0));
            }
            if (seq.size() > 1)
            {
                if (this.ca != null)
                {
                    this.pathlenconstraint = asn1integer.getinstance(seq.getobjectat(1));
                }
                else
                {
                    throw new illegalargumentexception("wrong sequence in constructor");
                }
            }
        }
    }

    public basicconstraints(
        boolean ca)
    {
        if (ca)
        {
            this.ca = asn1boolean.getinstance(true);
        }
        else
        {
            this.ca = null;
        }
        this.pathlenconstraint = null;
    }

    /**
     * create a ca=true object for the given path length constraint.
     * 
     * @param pathlenconstraint
     */
    public basicconstraints(
        int     pathlenconstraint)
    {
        this.ca = asn1boolean.getinstance(true);
        this.pathlenconstraint = new asn1integer(pathlenconstraint);
    }

    public boolean isca()
    {
        return (ca != null) && ca.istrue();
    }

    public biginteger getpathlenconstraint()
    {
        if (pathlenconstraint != null)
        {
            return pathlenconstraint.getvalue();
        }

        return null;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * basicconstraints := sequence {
     *    ca                  boolean default false,
     *    pathlenconstraint   integer (0..max) optional
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (ca != null)
        {
            v.add(ca);
        }

        if (pathlenconstraint != null)  // yes some people actually do this when ca is false...
        {
            v.add(pathlenconstraint);
        }

        return new dersequence(v);
    }

    public string tostring()
    {
        if (pathlenconstraint == null)
        {
            if (ca == null)
            {
                return "basicconstraints: isca(false)";
            }
            return "basicconstraints: isca(" + this.isca() + ")";
        }
        return "basicconstraints: isca(" + this.isca() + "), pathlenconstraint = " + pathlenconstraint.getvalue();
    }
}
