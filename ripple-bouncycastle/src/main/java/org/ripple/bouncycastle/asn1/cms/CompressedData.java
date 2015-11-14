package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/** 
 * rfc 3274 - cms compressed data.
 * <pre>
 * compresseddata ::= sequence {
 *  version cmsversion,
 *  compressionalgorithm compressionalgorithmidentifier,
 *  encapcontentinfo encapsulatedcontentinfo
 * }
 * </pre>
 */
public class compresseddata
    extends asn1object
{
    private asn1integer           version;
    private algorithmidentifier  compressionalgorithm;
    private contentinfo          encapcontentinfo;

    public compresseddata(
        algorithmidentifier compressionalgorithm,
        contentinfo         encapcontentinfo)
    {
        this.version = new asn1integer(0);
        this.compressionalgorithm = compressionalgorithm;
        this.encapcontentinfo = encapcontentinfo;
    }
    
    private compresseddata(
        asn1sequence seq)
    {
        this.version = (asn1integer)seq.getobjectat(0);
        this.compressionalgorithm = algorithmidentifier.getinstance(seq.getobjectat(1));
        this.encapcontentinfo = contentinfo.getinstance(seq.getobjectat(2));

    }

    /**
     * return a compresseddata object from a tagged object.
     *
     * @param _ato the tagged object holding the object we want.
     * @param _explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static compresseddata getinstance(
        asn1taggedobject _ato,
        boolean _explicit)
    {
        return getinstance(asn1sequence.getinstance(_ato, _explicit));
    }
    
    /**
     * return a compresseddata object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static compresseddata getinstance(
        object obj)
    {
        if (obj instanceof compresseddata)
        {
            return (compresseddata)obj;
        }

        if (obj != null)
        {
            return new compresseddata(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1integer getversion()
    {
        return version;
    }

    public algorithmidentifier getcompressionalgorithmidentifier()
    {
        return compressionalgorithm;
    }

    public contentinfo getencapcontentinfo()
    {
        return encapcontentinfo;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);
        v.add(compressionalgorithm);
        v.add(encapcontentinfo);

        return new bersequence(v);
    }
}
