package org.ripple.bouncycastle.asn1.pkcs;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * a pkcs#7 signed data object.
 */
public class signeddata
    extends asn1object
    implements pkcsobjectidentifiers
{
    private asn1integer              version;
    private asn1set                 digestalgorithms;
    private contentinfo             contentinfo;
    private asn1set                 certificates;
    private asn1set                 crls;
    private asn1set                 signerinfos;

    public static signeddata getinstance(
        object  o)
    {
        if (o instanceof signeddata)
        {
            return (signeddata)o;
        }
        else if (o != null)
        {
            return new signeddata(asn1sequence.getinstance(o));
        }

        return null;
    }

    public signeddata(
        asn1integer        _version,
        asn1set           _digestalgorithms,
        contentinfo       _contentinfo,
        asn1set           _certificates,
        asn1set           _crls,
        asn1set           _signerinfos)
    {
        version          = _version;
        digestalgorithms = _digestalgorithms;
        contentinfo      = _contentinfo;
        certificates     = _certificates;
        crls             = _crls;
        signerinfos      = _signerinfos;
    }

    public signeddata(
        asn1sequence seq)
    {
        enumeration     e = seq.getobjects();

        version = (asn1integer)e.nextelement();
        digestalgorithms = ((asn1set)e.nextelement());
        contentinfo = contentinfo.getinstance(e.nextelement());

        while (e.hasmoreelements())
        {
            asn1primitive o = (asn1primitive)e.nextelement();

            //
            // an interesting feature of signeddata is that there appear to be varying implementations...
            // for the moment we ignore anything which doesn't fit.
            //
            if (o instanceof asn1taggedobject)
            {
                asn1taggedobject tagged = (asn1taggedobject)o;

                switch (tagged.gettagno())
                {
                case 0:
                    certificates = asn1set.getinstance(tagged, false);
                    break;
                case 1:
                    crls = asn1set.getinstance(tagged, false);
                    break;
                default:
                    throw new illegalargumentexception("unknown tag value " + tagged.gettagno());
                }
            }
            else
            {
                signerinfos = (asn1set)o;
            }
        }
    }

    public asn1integer getversion()
    {
        return version;
    }

    public asn1set getdigestalgorithms()
    {
        return digestalgorithms;
    }

    public contentinfo getcontentinfo()
    {
        return contentinfo;
    }

    public asn1set getcertificates()
    {
        return certificates;
    }

    public asn1set getcrls()
    {
        return crls;
    }

    public asn1set getsignerinfos()
    {
        return signerinfos;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  signeddata ::= sequence {
     *      version version,
     *      digestalgorithms digestalgorithmidentifiers,
     *      contentinfo contentinfo,
     *      certificates
     *          [0] implicit extendedcertificatesandcertificates
     *                   optional,
     *      crls
     *          [1] implicit certificaterevocationlists optional,
     *      signerinfos signerinfos }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);
        v.add(digestalgorithms);
        v.add(contentinfo);

        if (certificates != null)
        {
            v.add(new dertaggedobject(false, 0, certificates));
        }

        if (crls != null)
        {
            v.add(new dertaggedobject(false, 1, crls));
        }

        v.add(signerinfos);

        return new bersequence(v);
    }
}
