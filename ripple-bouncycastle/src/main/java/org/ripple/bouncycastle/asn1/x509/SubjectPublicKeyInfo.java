package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the object that contains the public key stored in a certficate.
 * <p>
 * the getencoded() method in the public keys in the jce produces a der
 * encoded one of these.
 */
public class subjectpublickeyinfo
    extends asn1object
{
    private algorithmidentifier     algid;
    private derbitstring            keydata;

    public static subjectpublickeyinfo getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static subjectpublickeyinfo getinstance(
        object  obj)
    {
        if (obj instanceof subjectpublickeyinfo)
        {
            return (subjectpublickeyinfo)obj;
        }
        else if (obj != null)
        {
            return new subjectpublickeyinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public subjectpublickeyinfo(
        algorithmidentifier algid,
        asn1encodable       publickey)
        throws ioexception
    {
        this.keydata = new derbitstring(publickey);
        this.algid = algid;
    }

    public subjectpublickeyinfo(
        algorithmidentifier algid,
        byte[]              publickey)
    {
        this.keydata = new derbitstring(publickey);
        this.algid = algid;
    }

    public subjectpublickeyinfo(
        asn1sequence  seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        enumeration         e = seq.getobjects();

        this.algid = algorithmidentifier.getinstance(e.nextelement());
        this.keydata = derbitstring.getinstance(e.nextelement());
    }

    public algorithmidentifier getalgorithm()
    {
        return algid;
    }

    /**
     * @deprecated use getalgorithm()
     * @return    alg id.
     */
    public algorithmidentifier getalgorithmid()
    {
        return algid;
    }

    /**
     * for when the public key is an encoded object - if the bitstring
     * can't be decoded this routine throws an ioexception.
     *
     * @exception ioexception - if the bit string doesn't represent a der
     * encoded object.
     * @return the public key as an asn.1 primitive.
     */
    public asn1primitive parsepublickey()
        throws ioexception
    {
        asn1inputstream         ain = new asn1inputstream(keydata.getbytes());

        return ain.readobject();
    }

    /**
     * for when the public key is an encoded object - if the bitstring
     * can't be decoded this routine throws an ioexception.
     *
     * @exception ioexception - if the bit string doesn't represent a der
     * encoded object.
     * @deprecated use parsepublickey
     * @return the public key as an asn.1 primitive.
     */
    public asn1primitive getpublickey()
        throws ioexception
    {
        asn1inputstream         ain = new asn1inputstream(keydata.getbytes());

        return ain.readobject();
    }

    /**
     * for when the public key is raw bits.
     *
     * @return the public key as the raw bit string...
     */
    public derbitstring getpublickeydata()
    {
        return keydata;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * subjectpublickeyinfo ::= sequence {
     *                          algorithm algorithmidentifier,
     *                          publickey bit string }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(algid);
        v.add(keydata);

        return new dersequence(v);
    }
}
