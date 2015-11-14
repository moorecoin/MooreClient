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

/**
 * the extendedkeyusage object.
 * <pre>
 *      extendedkeyusage ::= sequence size (1..max) of keypurposeid
 * </pre>
 */
public class extendedkeyusage
    extends asn1object
{
    hashtable     usagetable = new hashtable();
    asn1sequence  seq;

    public static extendedkeyusage getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static extendedkeyusage getinstance(
        object obj)
    {
        if (obj instanceof extendedkeyusage) 
        {
            return (extendedkeyusage)obj;
        }
        else if (obj != null)
        {
            return new extendedkeyusage(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static extendedkeyusage fromextensions(extensions extensions)
    {
        return extendedkeyusage.getinstance(extensions.getextensionparsedvalue(extension.extendedkeyusage));
    }

    public extendedkeyusage(
        keypurposeid  usage)
    {
        this.seq = new dersequence(usage);

        this.usagetable.put(usage, usage);
    }
    
    private extendedkeyusage(
        asn1sequence  seq)
    {
        this.seq = seq;

        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1encodable o = (asn1encodable)e.nextelement();
            if (!(o.toasn1primitive() instanceof asn1objectidentifier))
            {
                throw new illegalargumentexception("only asn1objectidentifiers allowed in extendedkeyusage.");
            }
            this.usagetable.put(o, o);
        }
    }

    public extendedkeyusage(
        keypurposeid[]  usages)
    {
        asn1encodablevector v = new asn1encodablevector();

        for (int i = 0; i != usages.length; i++)
        {
            v.add(usages[i]);
            this.usagetable.put(usages[i], usages[i]);
        }

        this.seq = new dersequence(v);
    }

    /**
     * @deprecated use keypurposeid[] constructor.
     */
    public extendedkeyusage(
        vector usages)
    {
        asn1encodablevector v = new asn1encodablevector();
        enumeration         e = usages.elements();

        while (e.hasmoreelements())
        {
            asn1primitive  o = (asn1primitive)e.nextelement();

            v.add(o);
            this.usagetable.put(o, o);
        }

        this.seq = new dersequence(v);
    }

    public boolean haskeypurposeid(
        keypurposeid keypurposeid)
    {
        return (usagetable.get(keypurposeid) != null);
    }
    
    /**
     * returns all extended key usages.
     * the returned vector contains derobjectidentifiers.
     * @return an array with all key purposes.
     */
    public keypurposeid[] getusages()
    {
        keypurposeid[] temp = new keypurposeid[seq.size()];

        int i = 0;
        for (enumeration it = seq.getobjects(); it.hasmoreelements();)
        {
            temp[i++] = keypurposeid.getinstance(it.nextelement());
        }
        return temp;
    }

    public int size()
    {
        return usagetable.size();
    }
    
    public asn1primitive toasn1primitive()
    {
        return seq;
    }
}
