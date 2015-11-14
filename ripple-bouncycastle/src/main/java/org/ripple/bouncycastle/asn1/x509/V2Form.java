package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class v2form
    extends asn1object
{
    generalnames        issuername;
    issuerserial        basecertificateid;
    objectdigestinfo    objectdigestinfo;

    public static v2form getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static v2form getinstance(
        object  obj)
    {
        if (obj instanceof v2form)
        {
            return (v2form)obj;
        }
        else if (obj != null)
        {
            return new v2form(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    public v2form(
        generalnames    issuername)
    {
        this(issuername, null, null);
    }

    public v2form(
        generalnames    issuername,
        issuerserial    basecertificateid)
    {
        this(issuername, basecertificateid, null);
    }

    public v2form(
        generalnames    issuername,
        objectdigestinfo objectdigestinfo)
    {
        this(issuername, null, objectdigestinfo);
    }

    public v2form(
        generalnames    issuername,
        issuerserial    basecertificateid,
        objectdigestinfo objectdigestinfo)
    {
        this.issuername = issuername;
        this.basecertificateid = basecertificateid;
        this.objectdigestinfo = objectdigestinfo;
    }

    /**
     * @deprecated use getinstance().
     */
    public v2form(
        asn1sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }
        
        int    index = 0;

        if (!(seq.getobjectat(0) instanceof asn1taggedobject))
        {
            index++;
            this.issuername = generalnames.getinstance(seq.getobjectat(0));
        }

        for (int i = index; i != seq.size(); i++)
        {
            asn1taggedobject o = asn1taggedobject.getinstance(seq.getobjectat(i));
            if (o.gettagno() == 0)
            {
                basecertificateid = issuerserial.getinstance(o, false);
            }
            else if (o.gettagno() == 1)
            {
                objectdigestinfo = objectdigestinfo.getinstance(o, false);
            }
            else 
            {
                throw new illegalargumentexception("bad tag number: "
                        + o.gettagno());
            }
        }
    }
    
    public generalnames getissuername()
    {
        return issuername;
    }

    public issuerserial getbasecertificateid()
    {
        return basecertificateid;
    }

    public objectdigestinfo getobjectdigestinfo()
    {
        return objectdigestinfo;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  v2form ::= sequence {
     *       issuername            generalnames  optional,
     *       basecertificateid     [0] issuerserial  optional,
     *       objectdigestinfo      [1] objectdigestinfo  optional
     *         -- issuername must be present in this profile
     *         -- basecertificateid and objectdigestinfo must not
     *         -- be present in this profile
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (issuername != null)
        {
            v.add(issuername);
        }

        if (basecertificateid != null)
        {
            v.add(new dertaggedobject(false, 0, basecertificateid));
        }

        if (objectdigestinfo != null)
        {
            v.add(new dertaggedobject(false, 1, objectdigestinfo));
        }

        return new dersequence(v);
    }
}
