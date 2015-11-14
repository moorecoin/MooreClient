package org.ripple.bouncycastle.pqc.asn1;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.util.arrays;

/**
 * this class implements an asn.1 encoded gmss public key. the asn.1 definition
 * of this structure is:
 * <p/>
 * <pre>
 *  gmsspublickey        ::= sequence{
 *      version         integer
 *      publickey       octet string
 *  }
 * </pre>
 */
public class gmsspublickey
    extends asn1object
{
    private asn1integer version;
    private byte[] publickey;

    private gmsspublickey(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("size of seq = " + seq.size());
        }

        this.version = asn1integer.getinstance(seq.getobjectat(0));
        this.publickey = asn1octetstring.getinstance(seq.getobjectat(1)).getoctets();
    }

    public gmsspublickey(byte[] publickeybytes)
    {
        this.version = new asn1integer(0);
        this.publickey = publickeybytes;
    }

    public static gmsspublickey getinstance(object o)
    {
        if (o instanceof gmsspublickey)
        {
            return (gmsspublickey)o;
        }
        else if (o != null)
        {
            return new gmsspublickey(asn1sequence.getinstance(o));
        }

        return null;
    }

    public byte[] getpublickey()
    {
        return arrays.clone(publickey);
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);
        v.add(new deroctetstring(publickey));

        return new dersequence(v);
    }
}
