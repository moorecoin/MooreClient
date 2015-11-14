package org.ripple.bouncycastle.asn1.cms;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class authenticateddata
    extends asn1object
{
    private asn1integer version;
    private originatorinfo originatorinfo;
    private asn1set recipientinfos;
    private algorithmidentifier macalgorithm;
    private algorithmidentifier digestalgorithm;
    private contentinfo encapsulatedcontentinfo;
    private asn1set authattrs;
    private asn1octetstring mac;
    private asn1set unauthattrs;

    public authenticateddata(
        originatorinfo originatorinfo,
        asn1set recipientinfos,
        algorithmidentifier macalgorithm,
        algorithmidentifier digestalgorithm,
        contentinfo encapsulatedcontent,
        asn1set authattrs,
        asn1octetstring mac,
        asn1set unauthattrs)
    {
        if (digestalgorithm != null || authattrs != null)
        {
            if (digestalgorithm == null || authattrs == null)
            {
                throw new illegalargumentexception("digestalgorithm and authattrs must be set together");
            }
        }

        version = new asn1integer(calculateversion(originatorinfo));
        
        this.originatorinfo = originatorinfo;
        this.macalgorithm = macalgorithm;
        this.digestalgorithm = digestalgorithm;
        this.recipientinfos = recipientinfos;
        this.encapsulatedcontentinfo = encapsulatedcontent;
        this.authattrs = authattrs;
        this.mac = mac;
        this.unauthattrs = unauthattrs;
    }

    public authenticateddata(
        asn1sequence seq)
    {
        int index = 0;

        version = (asn1integer)seq.getobjectat(index++);

        object tmp = seq.getobjectat(index++);

        if (tmp instanceof asn1taggedobject)
        {
            originatorinfo = originatorinfo.getinstance((asn1taggedobject)tmp, false);
            tmp = seq.getobjectat(index++);
        }

        recipientinfos = asn1set.getinstance(tmp);
        macalgorithm = algorithmidentifier.getinstance(seq.getobjectat(index++));

        tmp = seq.getobjectat(index++);

        if (tmp instanceof asn1taggedobject)
        {
            digestalgorithm = algorithmidentifier.getinstance((asn1taggedobject)tmp, false);
            tmp = seq.getobjectat(index++);
        }

        encapsulatedcontentinfo = contentinfo.getinstance(tmp);

        tmp = seq.getobjectat(index++);

        if (tmp instanceof asn1taggedobject)
        {
            authattrs = asn1set.getinstance((asn1taggedobject)tmp, false);
            tmp = seq.getobjectat(index++);
        }

        mac = asn1octetstring.getinstance(tmp);
        
        if (seq.size() > index)
        {
            unauthattrs = asn1set.getinstance((asn1taggedobject)seq.getobjectat(index), false);
        }
    }

    /**
     * return an authenticateddata object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws illegalargumentexception if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static authenticateddata getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * return an authenticateddata object from the given object.
     *
     * @param obj the object we want converted.
     * @throws illegalargumentexception if the object cannot be converted.
     */
    public static authenticateddata getinstance(
        object obj)
    {
        if (obj == null || obj instanceof authenticateddata)
        {
            return (authenticateddata)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new authenticateddata((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid authenticateddata: " + obj.getclass().getname());
    }

    public asn1integer getversion()
    {
        return version;
    }

    public originatorinfo getoriginatorinfo()
    {
        return originatorinfo;
    }

    public asn1set getrecipientinfos()
    {
        return recipientinfos;
    }

    public algorithmidentifier getmacalgorithm()
    {
        return macalgorithm;
    }

    public algorithmidentifier getdigestalgorithm()
    {
        return digestalgorithm;
    }

    public contentinfo getencapsulatedcontentinfo()
    {
        return encapsulatedcontentinfo;
    }

    public asn1set getauthattrs()
    {
        return authattrs;
    }

    public asn1octetstring getmac()
    {
        return mac;
    }

    public asn1set getunauthattrs()
    {
        return unauthattrs;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * authenticateddata ::= sequence {
     *       version cmsversion,
     *       originatorinfo [0] implicit originatorinfo optional,
     *       recipientinfos recipientinfos,
     *       macalgorithm messageauthenticationcodealgorithm,
     *       digestalgorithm [1] digestalgorithmidentifier optional,
     *       encapcontentinfo encapsulatedcontentinfo,
     *       authattrs [2] implicit authattributes optional,
     *       mac messageauthenticationcode,
     *       unauthattrs [3] implicit unauthattributes optional }
     *
     * authattributes ::= set size (1..max) of attribute
     *
     * unauthattributes ::= set size (1..max) of attribute
     *
     * messageauthenticationcode ::= octet string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);

        if (originatorinfo != null)
        {
            v.add(new dertaggedobject(false, 0, originatorinfo));
        }

        v.add(recipientinfos);
        v.add(macalgorithm);

        if (digestalgorithm != null)
        {
            v.add(new dertaggedobject(false, 1, digestalgorithm));
        }

        v.add(encapsulatedcontentinfo);

        if (authattrs != null)
        {
            v.add(new dertaggedobject(false, 2, authattrs));
        }

        v.add(mac);

        if (unauthattrs != null)
        {
            v.add(new dertaggedobject(false, 3, unauthattrs));
        }

        return new bersequence(v);
    }

    public static int calculateversion(originatorinfo originfo)
    {
        if (originfo == null)
        {
            return 0;
        }
        else
        {
            int ver = 0;

            for (enumeration e = originfo.getcertificates().getobjects(); e.hasmoreelements();)
            {
                object obj = e.nextelement();

                if (obj instanceof asn1taggedobject)
                {
                    asn1taggedobject tag = (asn1taggedobject)obj;

                    if (tag.gettagno() == 2)
                    {
                        ver = 1;
                    }
                    else if (tag.gettagno() == 3)
                    {
                        ver = 3;
                        break;
                    }
                }
            }

            if (originfo.getcrls() != null)
            {
                for (enumeration e = originfo.getcrls().getobjects(); e.hasmoreelements();)
                {
                    object obj = e.nextelement();

                    if (obj instanceof asn1taggedobject)
                    {
                        asn1taggedobject tag = (asn1taggedobject)obj;

                        if (tag.gettagno() == 1)
                        {
                            ver = 3;
                            break;
                        }
                    }
                }
            }

            return ver;
        }
    }
}
