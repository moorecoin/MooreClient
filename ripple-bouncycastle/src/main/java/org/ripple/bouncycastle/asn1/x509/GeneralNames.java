package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class generalnames
    extends asn1object
{
    private final generalname[] names;

    public static generalnames getinstance(
        object  obj)
    {
        if (obj instanceof generalnames)
        {
            return (generalnames)obj;
        }

        if (obj != null)
        {
            return new generalnames(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static generalnames getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static generalnames fromextensions(extensions extensions, asn1objectidentifier extoid)
    {
        return generalnames.getinstance(extensions.getextensionparsedvalue(extoid));
    }

    /**
     * construct a generalnames object containing one generalname.
     * 
     * @param name the name to be contained.
     */
    public generalnames(
        generalname  name)
    {
        this.names = new generalname[] { name };
    }


    public generalnames(
        generalname[]  names)
    {
        this.names = names;
    }

    private generalnames(
        asn1sequence  seq)
    {
        this.names = new generalname[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            names[i] = generalname.getinstance(seq.getobjectat(i));
        }
    }

    public generalname[] getnames()
    {
        generalname[] tmp = new generalname[names.length];

        system.arraycopy(names, 0, tmp, 0, names.length);

        return tmp;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * generalnames ::= sequence size {1..max} of generalname
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return new dersequence(names);
    }

    public string tostring()
    {
        stringbuffer  buf = new stringbuffer();
        string        sep = system.getproperty("line.separator");

        buf.append("generalnames:");
        buf.append(sep);

        for (int i = 0; i != names.length; i++)
        {
            buf.append("    ");
            buf.append(names[i]);
            buf.append(sep);
        }
        return buf.tostring();
    }
}
