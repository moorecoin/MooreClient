package org.ripple.bouncycastle.asn1.cms;

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

public class envelopeddata
    extends asn1object
{
    private asn1integer              version;
    private originatorinfo          originatorinfo;
    private asn1set                 recipientinfos;
    private encryptedcontentinfo    encryptedcontentinfo;
    private asn1set                 unprotectedattrs;

    public envelopeddata(
        originatorinfo          originatorinfo,
        asn1set                 recipientinfos,
        encryptedcontentinfo    encryptedcontentinfo,
        asn1set                 unprotectedattrs)
    {
        version = new asn1integer(calculateversion(originatorinfo, recipientinfos, unprotectedattrs));

        this.originatorinfo = originatorinfo;
        this.recipientinfos = recipientinfos;
        this.encryptedcontentinfo = encryptedcontentinfo;
        this.unprotectedattrs = unprotectedattrs;
    }

    public envelopeddata(
        originatorinfo          originatorinfo,
        asn1set                 recipientinfos,
        encryptedcontentinfo    encryptedcontentinfo,
        attributes              unprotectedattrs)
    {
        version = new asn1integer(calculateversion(originatorinfo, recipientinfos, asn1set.getinstance(unprotectedattrs)));

        this.originatorinfo = originatorinfo;
        this.recipientinfos = recipientinfos;
        this.encryptedcontentinfo = encryptedcontentinfo;
        this.unprotectedattrs = asn1set.getinstance(unprotectedattrs);
    }

    /**
     * @deprecated use getinstance()
     */
    public envelopeddata(
        asn1sequence seq)
    {
        int     index = 0;
        
        version = (asn1integer)seq.getobjectat(index++);
        
        object  tmp = seq.getobjectat(index++);

        if (tmp instanceof asn1taggedobject)
        {
            originatorinfo = originatorinfo.getinstance((asn1taggedobject)tmp, false);
            tmp = seq.getobjectat(index++);
        }

        recipientinfos = asn1set.getinstance(tmp);
        
        encryptedcontentinfo = encryptedcontentinfo.getinstance(seq.getobjectat(index++));
        
        if(seq.size() > index)
        {
            unprotectedattrs = asn1set.getinstance((asn1taggedobject)seq.getobjectat(index), false);
        }
    }
    
    /**
     * return an envelopeddata object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static envelopeddata getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return an envelopeddata object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static envelopeddata getinstance(
        object obj)
    {
        if (obj instanceof envelopeddata)
        {
            return (envelopeddata)obj;
        }
        
        if (obj != null)
        {
            return new envelopeddata(asn1sequence.getinstance(obj));
        }
        
        return null;
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

    public encryptedcontentinfo getencryptedcontentinfo()
    {
        return encryptedcontentinfo;
    }

    public asn1set getunprotectedattrs()
    {
        return unprotectedattrs;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * envelopeddata ::= sequence {
     *     version cmsversion,
     *     originatorinfo [0] implicit originatorinfo optional,
     *     recipientinfos recipientinfos,
     *     encryptedcontentinfo encryptedcontentinfo,
     *     unprotectedattrs [1] implicit unprotectedattributes optional 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();
        
        v.add(version);

        if (originatorinfo != null)
        {
            v.add(new dertaggedobject(false, 0, originatorinfo));
        }

        v.add(recipientinfos);
        v.add(encryptedcontentinfo);

        if (unprotectedattrs != null)
        {
            v.add(new dertaggedobject(false, 1, unprotectedattrs));
        }
        
        return new bersequence(v);
    }

    public static int calculateversion(originatorinfo originatorinfo, asn1set recipientinfos, asn1set unprotectedattrs)
    {
        int version;

        if (originatorinfo != null || unprotectedattrs != null)
        {
            version = 2;
        }
        else
        {
            version = 0;

            enumeration e = recipientinfos.getobjects();

            while (e.hasmoreelements())
            {
                recipientinfo   ri = recipientinfo.getinstance(e.nextelement());

                if (ri.getversion().getvalue().intvalue() != version)
                {
                    version = 2;
                    break;
                }
            }
        }

        return version;
    }
}
