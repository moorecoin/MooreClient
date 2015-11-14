package org.ripple.bouncycastle.asn1.sec;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.util.bigintegers;

/**
 * the elliptic curve private key object from sec 1
 */
public class ecprivatekey
    extends asn1object
{
    private asn1sequence seq;

    private ecprivatekey(
        asn1sequence seq)
    {
        this.seq = seq;
    }

    public static ecprivatekey getinstance(
        object obj)
    {
        if (obj instanceof ecprivatekey)
        {
            return (ecprivatekey)obj;
        }

        if (obj != null)
        {
            return new ecprivatekey(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public ecprivatekey(
        biginteger key)
    {
        byte[] bytes = bigintegers.asunsignedbytearray(key);

        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(1));
        v.add(new deroctetstring(bytes));

        seq = new dersequence(v);
    }

    public ecprivatekey(
        biginteger key,
        asn1object parameters)
    {
        this(key, null, parameters);
    }

    public ecprivatekey(
        biginteger key,
        derbitstring publickey,
        asn1object parameters)
    {
        byte[] bytes = bigintegers.asunsignedbytearray(key);

        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(1));
        v.add(new deroctetstring(bytes));

        if (parameters != null)
        {
            v.add(new dertaggedobject(true, 0, parameters));
        }

        if (publickey != null)
        {
            v.add(new dertaggedobject(true, 1, publickey));
        }

        seq = new dersequence(v);
    }

    public biginteger getkey()
    {
        asn1octetstring octs = (asn1octetstring)seq.getobjectat(1);

        return new biginteger(1, octs.getoctets());
    }

    public derbitstring getpublickey()
    {
        return (derbitstring)getobjectintag(1);
    }

    public asn1primitive getparameters()
    {
        return getobjectintag(0);
    }

    private asn1primitive getobjectintag(int tagno)
    {
        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1encodable obj = (asn1encodable)e.nextelement();

            if (obj instanceof asn1taggedobject)
            {
                asn1taggedobject tag = (asn1taggedobject)obj;
                if (tag.gettagno() == tagno)
                {
                    return tag.getobject().toasn1primitive();
                }
            }
        }
        return null;
    }

    /**
     * ecprivatekey ::= sequence {
     *     version integer { ecprivkeyver1(1) } (ecprivkeyver1),
     *     privatekey octet string,
     *     parameters [0] parameters optional,
     *     publickey [1] bit string optional }
     */
    public asn1primitive toasn1primitive()
    {
        return seq;
    }
}
