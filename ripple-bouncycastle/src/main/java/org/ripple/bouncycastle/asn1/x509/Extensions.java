package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class extensions
    extends asn1object
{
    private hashtable extensions = new hashtable();
    private vector ordering = new vector();

    public static extensions getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static extensions getinstance(
        object obj)
    {
        if (obj instanceof extensions)
        {
            return (extensions)obj;
        }
        else if (obj != null)
        {
            return new extensions(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the extensions are a list of constructed sequences, either with (oid, octetstring) or (oid, boolean, octetstring)
     */
    private extensions(
        asn1sequence seq)
    {
        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            extension ext = extension.getinstance(e.nextelement());

            extensions.put(ext.getextnid(), ext);
            ordering.addelement(ext.getextnid());
        }
    }

    /**
     * base constructor
     *
     * @param extension a single extension.
     */
    public extensions(
        extension extension)
    {
        this.ordering.addelement(extension.getextnid());
        this.extensions.put(extension.getextnid(), extension);
    }

    /**
     * base constructor
     *
     * @param extensions an array of extensions.
     */
    public extensions(
        extension[] extensions)
    {
        for (int i = 0; i != extensions.length; i++)
        {
            extension ext = extensions[i];

            this.ordering.addelement(ext.getextnid());
            this.extensions.put(ext.getextnid(), ext);
        }
    }

    /**
     * return an enumeration of the extension field's object ids.
     */
    public enumeration oids()
    {
        return ordering.elements();
    }

    /**
     * return the extension represented by the object identifier
     * passed in.
     *
     * @return the extension if it's present, null otherwise.
     */
    public extension getextension(
        asn1objectidentifier oid)
    {
        return (extension)extensions.get(oid);
    }

    /**
     * return the parsed value of the extension represented by the object identifier
     * passed in.
     *
     * @return the parsed value of the extension if it's present, null otherwise.
     */
    public asn1encodable getextensionparsedvalue(asn1objectidentifier oid)
    {
        extension ext = this.getextension(oid);

        if (ext != null)
        {
            return ext.getparsedvalue();
        }

        return null;
    }

    /**
     * <pre>
     *     extensions        ::=   sequence size (1..max) of extension
     *
     *     extension         ::=   sequence {
     *        extnid            extension.&amp;id ({extensionset}),
     *        critical          boolean default false,
     *        extnvalue         octet string }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        enumeration e = ordering.elements();

        while (e.hasmoreelements())
        {
            asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
            extension ext = (extension)extensions.get(oid);

            vec.add(ext);
        }

        return new dersequence(vec);
    }

    public boolean equivalent(
        extensions other)
    {
        if (extensions.size() != other.extensions.size())
        {
            return false;
        }

        enumeration e1 = extensions.keys();

        while (e1.hasmoreelements())
        {
            object key = e1.nextelement();

            if (!extensions.get(key).equals(other.extensions.get(key)))
            {
                return false;
            }
        }

        return true;
    }

    public asn1objectidentifier[] getextensionoids()
    {
        return tooidarray(ordering);
    }

    public asn1objectidentifier[] getnoncriticalextensionoids()
    {
        return getextensionoids(false);
    }

    public asn1objectidentifier[] getcriticalextensionoids()
    {
        return getextensionoids(true);
    }

    private asn1objectidentifier[] getextensionoids(boolean iscritical)
    {
        vector oidvec = new vector();

        for (int i = 0; i != ordering.size(); i++)
        {
            object oid = ordering.elementat(i);

            if (((extension)extensions.get(oid)).iscritical() == iscritical)
            {
                oidvec.addelement(oid);
            }
        }

        return tooidarray(oidvec);
    }

    private asn1objectidentifier[] tooidarray(vector oidvec)
    {
        asn1objectidentifier[] oids = new asn1objectidentifier[oidvec.size()];

        for (int i = 0; i != oids.length; i++)
        {
            oids[i] = (asn1objectidentifier)oidvec.elementat(i);
        }
        return oids;
    }
}
