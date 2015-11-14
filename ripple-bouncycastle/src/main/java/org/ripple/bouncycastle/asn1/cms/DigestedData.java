package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/** 
 * rfc 3274 - cms digest data.
 * <pre>
 * digesteddata ::= sequence {
 *               version cmsversion,
 *               digestalgorithm digestalgorithmidentifier,
 *               encapcontentinfo encapsulatedcontentinfo,
 *               digest digest }
 * </pre>
 */
public class digesteddata
    extends asn1object
{
    private asn1integer           version;
    private algorithmidentifier  digestalgorithm;
    private contentinfo          encapcontentinfo;
    private asn1octetstring      digest;

    public digesteddata(
        algorithmidentifier digestalgorithm,
        contentinfo encapcontentinfo,
        byte[]      digest)
    {
        this.version = new asn1integer(0);
        this.digestalgorithm = digestalgorithm;
        this.encapcontentinfo = encapcontentinfo;
        this.digest = new deroctetstring(digest);
    }

    private digesteddata(
        asn1sequence seq)
    {
        this.version = (asn1integer)seq.getobjectat(0);
        this.digestalgorithm = algorithmidentifier.getinstance(seq.getobjectat(1));
        this.encapcontentinfo = contentinfo.getinstance(seq.getobjectat(2));
        this.digest = asn1octetstring.getinstance(seq.getobjectat(3));
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
    public static digesteddata getinstance(
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
    public static digesteddata getinstance(
        object obj)
    {
        if (obj instanceof digesteddata)
        {
            return (digesteddata)obj;
        }
        
        if (obj != null)
        {
            return new digesteddata(asn1sequence.getinstance(obj));
        }
        
        return null;
    }

    public asn1integer getversion()
    {
        return version;
    }

    public algorithmidentifier getdigestalgorithm()
    {
        return digestalgorithm;
    }

    public contentinfo getencapcontentinfo()
    {
        return encapcontentinfo;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);
        v.add(digestalgorithm);
        v.add(encapcontentinfo);
        v.add(digest);

        return new bersequence(v);
    }

    public byte[] getdigest()
    {
        return digest.getoctets();
    }
}
