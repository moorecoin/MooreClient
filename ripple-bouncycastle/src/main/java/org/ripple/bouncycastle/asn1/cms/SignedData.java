package org.ripple.bouncycastle.asn1.cms;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.berset;
import org.ripple.bouncycastle.asn1.bertaggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * a signed data object.
 */
public class signeddata
    extends asn1object
{
    private static final asn1integer version_1 = new asn1integer(1);
    private static final asn1integer version_3 = new asn1integer(3);
    private static final asn1integer version_4 = new asn1integer(4);
    private static final asn1integer version_5 = new asn1integer(5);

    private asn1integer version;
    private asn1set     digestalgorithms;
    private contentinfo contentinfo;
    private asn1set     certificates;
    private asn1set     crls;
    private asn1set     signerinfos;
    private boolean certsber;
    private boolean        crlsber;

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
        asn1set     digestalgorithms,
        contentinfo contentinfo,
        asn1set     certificates,
        asn1set     crls,
        asn1set     signerinfos)
    {
        this.version = calculateversion(contentinfo.getcontenttype(), certificates, crls, signerinfos);
        this.digestalgorithms = digestalgorithms;
        this.contentinfo = contentinfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerinfos = signerinfos;
        this.crlsber = crls instanceof berset;
        this.certsber = certificates instanceof berset;
    }


    // rfc3852, section 5.1:
    // if ((certificates is present) and
    //    (any certificates with a type of other are present)) or
    //    ((crls is present) and
    //    (any crls with a type of other are present))
    // then version must be 5
    // else
    //    if (certificates is present) and
    //       (any version 2 attribute certificates are present)
    //    then version must be 4
    //    else
    //       if ((certificates is present) and
    //          (any version 1 attribute certificates are present)) or
    //          (any signerinfo structures are version 3) or
    //          (encapcontentinfo econtenttype is other than id-data)
    //       then version must be 3
    //       else version must be 1
    //
    private asn1integer calculateversion(
        asn1objectidentifier contentoid,
        asn1set certs,
        asn1set crls,
        asn1set signerinfs)
    {
        boolean othercert = false;
        boolean othercrl = false;
        boolean attrcertv1found = false;
        boolean attrcertv2found = false;

        if (certs != null)
        {
            for (enumeration en = certs.getobjects(); en.hasmoreelements();)
            {
                object obj = en.nextelement();
                if (obj instanceof asn1taggedobject)
                {
                    asn1taggedobject tagged = asn1taggedobject.getinstance(obj);

                    if (tagged.gettagno() == 1)
                    {
                        attrcertv1found = true;
                    }
                    else if (tagged.gettagno() == 2)
                    {
                        attrcertv2found = true;
                    }
                    else if (tagged.gettagno() == 3)
                    {
                        othercert = true;
                    }
                }
            }
        }

        if (othercert)
        {
            return new asn1integer(5);
        }

        if (crls != null)         // no need to check if othercert is true
        {
            for (enumeration en = crls.getobjects(); en.hasmoreelements();)
            {
                object obj = en.nextelement();
                if (obj instanceof asn1taggedobject)
                {
                    othercrl = true;
                }
            }
        }

        if (othercrl)
        {
            return version_5;
        }

        if (attrcertv2found)
        {
            return version_4;
        }

        if (attrcertv1found)
        {
            return version_3;
        }

        if (checkforversion3(signerinfs))
        {
            return version_3;
        }

        if (!cmsobjectidentifiers.data.equals(contentoid))
        {
            return version_3;
        }

        return version_1;
    }

    private boolean checkforversion3(asn1set signerinfs)
    {
        for (enumeration e = signerinfs.getobjects(); e.hasmoreelements();)
        {
            signerinfo s = signerinfo.getinstance(e.nextelement());

            if (s.getversion().getvalue().intvalue() == 3)
            {
                return true;
            }
        }

        return false;
    }

    private signeddata(
        asn1sequence seq)
    {
        enumeration     e = seq.getobjects();

        version = asn1integer.getinstance(e.nextelement());
        digestalgorithms = ((asn1set)e.nextelement());
        contentinfo = contentinfo.getinstance(e.nextelement());

        while (e.hasmoreelements())
        {
            asn1primitive o = (asn1primitive)e.nextelement();

            //
            // an interesting feature of signeddata is that there appear
            // to be varying implementations...
            // for the moment we ignore anything which doesn't fit.
            //
            if (o instanceof asn1taggedobject)
            {
                asn1taggedobject tagged = (asn1taggedobject)o;

                switch (tagged.gettagno())
                {
                case 0:
                    certsber = tagged instanceof bertaggedobject;
                    certificates = asn1set.getinstance(tagged, false);
                    break;
                case 1:
                    crlsber = tagged instanceof bertaggedobject;
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

    public contentinfo getencapcontentinfo()
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
     * signeddata ::= sequence {
     *     version cmsversion,
     *     digestalgorithms digestalgorithmidentifiers,
     *     encapcontentinfo encapsulatedcontentinfo,
     *     certificates [0] implicit certificateset optional,
     *     crls [1] implicit certificaterevocationlists optional,
     *     signerinfos signerinfos
     *   }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(digestalgorithms);
        v.add(contentinfo);

        if (certificates != null)
        {
            if (certsber)
            {
                v.add(new bertaggedobject(false, 0, certificates));
            }
            else
            {
                v.add(new dertaggedobject(false, 0, certificates));
            }
        }

        if (crls != null)
        {
            if (crlsber)
            {
                v.add(new bertaggedobject(false, 1, crls));
            }
            else
            {
                v.add(new dertaggedobject(false, 1, crls));
            }
        }

        v.add(signerinfos);

        return new bersequence(v);
    }
}
