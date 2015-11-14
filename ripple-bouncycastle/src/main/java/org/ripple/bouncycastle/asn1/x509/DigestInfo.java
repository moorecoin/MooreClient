package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the digestinfo object.
 * <pre>
 * digestinfo::=sequence{
 *          digestalgorithm  algorithmidentifier,
 *          digest octet string }
 * </pre>
 */
public class digestinfo
    extends asn1object
{
    private byte[]                  digest;
    private algorithmidentifier     algid;

    public static digestinfo getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static digestinfo getinstance(
        object  obj)
    {
        if (obj instanceof digestinfo)
        {
            return (digestinfo)obj;
        }
        else if (obj != null)
        {
            return new digestinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public digestinfo(
        algorithmidentifier  algid,
        byte[]               digest)
    {
        this.digest = digest;
        this.algid = algid;
    }

    public digestinfo(
        asn1sequence  obj)
    {
        enumeration             e = obj.getobjects();

        algid = algorithmidentifier.getinstance(e.nextelement());
        digest = asn1octetstring.getinstance(e.nextelement()).getoctets();
    }

    public algorithmidentifier getalgorithmid()
    {
        return algid;
    }

    public byte[] getdigest()
    {
        return digest;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(algid);
        v.add(new deroctetstring(digest));

        return new dersequence(v);
    }
}
