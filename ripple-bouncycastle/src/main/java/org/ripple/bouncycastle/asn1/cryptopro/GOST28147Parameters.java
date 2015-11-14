package org.ripple.bouncycastle.asn1.cryptopro;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class gost28147parameters
    extends asn1object
{
    asn1octetstring iv;
    asn1objectidentifier paramset;

    public static gost28147parameters getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static gost28147parameters getinstance(
        object obj)
    {
        if(obj == null || obj instanceof gost28147parameters)
        {
            return (gost28147parameters)obj;
        }

        if(obj instanceof asn1sequence)
        {
            return new gost28147parameters((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid gost3410parameter: " + obj.getclass().getname());
    }

    public gost28147parameters(
        asn1sequence  seq)
    {
        enumeration     e = seq.getobjects();

        iv = (asn1octetstring)e.nextelement();
        paramset = (asn1objectidentifier)e.nextelement();
    }

    /**
     * <pre>
     * gost28147-89-parameters ::=
     *               sequence {
     *                       iv                   gost28147-89-iv,
     *                       encryptionparamset   object identifier
     *                }
     *
     *   gost28147-89-iv ::= octet string (size (8))
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(iv);
        v.add(paramset);

        return new dersequence(v);
    }
}
