package org.ripple.bouncycastle.asn1.cms;

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

public class authenvelopeddata
    extends asn1object
{
    private asn1integer version;
    private originatorinfo originatorinfo;
    private asn1set recipientinfos;
    private encryptedcontentinfo authencryptedcontentinfo;
    private asn1set authattrs;
    private asn1octetstring mac;
    private asn1set unauthattrs;

    public authenvelopeddata(
        originatorinfo originatorinfo,
        asn1set recipientinfos,
        encryptedcontentinfo authencryptedcontentinfo,
        asn1set authattrs,
        asn1octetstring mac,
        asn1set unauthattrs)
    {
        // "it must be set to 0."
        this.version = new asn1integer(0);

        this.originatorinfo = originatorinfo;

        // todo
        // "there must be at least one element in the collection."
        this.recipientinfos = recipientinfos;

        this.authencryptedcontentinfo = authencryptedcontentinfo;

        // todo
        // "the authattrs must be present if the content type carried in
        // encryptedcontentinfo is not id-data."
        this.authattrs = authattrs;

        this.mac = mac;

        this.unauthattrs = unauthattrs;
    }

    public authenvelopeddata(
        asn1sequence seq)
    {
        int index = 0;

        // todo
        // "it must be set to 0."
        asn1primitive tmp = seq.getobjectat(index++).toasn1primitive();
        version = (asn1integer)tmp;

        tmp = seq.getobjectat(index++).toasn1primitive();
        if (tmp instanceof asn1taggedobject)
        {
            originatorinfo = originatorinfo.getinstance((asn1taggedobject)tmp, false);
            tmp = seq.getobjectat(index++).toasn1primitive();
        }

        // todo
        // "there must be at least one element in the collection."
        recipientinfos = asn1set.getinstance(tmp);

        tmp = seq.getobjectat(index++).toasn1primitive();
        authencryptedcontentinfo = encryptedcontentinfo.getinstance(tmp);

        tmp = seq.getobjectat(index++).toasn1primitive();
        if (tmp instanceof asn1taggedobject)
        {
            authattrs = asn1set.getinstance((asn1taggedobject)tmp, false);
            tmp = seq.getobjectat(index++).toasn1primitive();
        }
        else
        {
            // todo
            // "the authattrs must be present if the content type carried in
            // encryptedcontentinfo is not id-data."
        }

        mac = asn1octetstring.getinstance(tmp);

        if (seq.size() > index)
        {
            tmp = seq.getobjectat(index++).toasn1primitive();
            unauthattrs = asn1set.getinstance((asn1taggedobject)tmp, false);
        }
    }

    /**
     * return an authenvelopeddata object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws illegalargumentexception if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static authenvelopeddata getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * return an authenvelopeddata object from the given object.
     *
     * @param obj the object we want converted.
     * @throws illegalargumentexception if the object cannot be converted.
     */
    public static authenvelopeddata getinstance(
        object obj)
    {
        if (obj == null || obj instanceof authenvelopeddata)
        {
            return (authenvelopeddata)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new authenvelopeddata((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid authenvelopeddata: " + obj.getclass().getname());
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

    public encryptedcontentinfo getauthencryptedcontentinfo()
    {
        return authencryptedcontentinfo;
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
     * authenvelopeddata ::= sequence {
     *   version cmsversion,
     *   originatorinfo [0] implicit originatorinfo optional,
     *   recipientinfos recipientinfos,
     *   authencryptedcontentinfo encryptedcontentinfo,
     *   authattrs [1] implicit authattributes optional,
     *   mac messageauthenticationcode,
     *   unauthattrs [2] implicit unauthattributes optional }
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
        v.add(authencryptedcontentinfo);

        // "authattrs optionally contains the authenticated attributes."
        if (authattrs != null)
        {
            // "authattributes must be der encoded, even if the rest of the
            // authenvelopeddata structure is ber encoded."
            v.add(new dertaggedobject(false, 1, authattrs));
        }

        v.add(mac);

        // "unauthattrs optionally contains the unauthenticated attributes."
        if (unauthattrs != null)
        {
            v.add(new dertaggedobject(false, 2, unauthattrs));
        }

        return new bersequence(v);
    }
}
