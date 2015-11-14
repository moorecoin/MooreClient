package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * the holder object.
 * <p>
 * for an v2 attribute certificate this is:
 * 
 * <pre>
 *            holder ::= sequence {
 *                  basecertificateid   [0] issuerserial optional,
 *                           -- the issuer and serial number of
 *                           -- the holder's public key certificate
 *                  entityname          [1] generalnames optional,
 *                           -- the name of the claimant or role
 *                  objectdigestinfo    [2] objectdigestinfo optional
 *                           -- used to directly authenticate the holder,
 *                           -- for example, an executable
 *            }
 * </pre>
 * 
 * <p>
 * for an v1 attribute certificate this is:
 * 
 * <pre>
 *         subject choice {
 *          basecertificateid [0] issuerserial,
 *          -- associated with a public key certificate
 *          subjectname [1] generalnames },
 *          -- associated with a name
 * </pre>
 */
public class holder
    extends asn1object
{
    public static final int v1_certificate_holder = 0;
    public static final int v2_certificate_holder = 1;

    issuerserial basecertificateid;

    generalnames entityname;

    objectdigestinfo objectdigestinfo;

    private int version = v2_certificate_holder;

    public static holder getinstance(object obj)
    {
        if (obj instanceof holder)
        {
            return (holder)obj;
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new holder(asn1taggedobject.getinstance(obj));
        }
        else if (obj != null)
        {
            return new holder(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor for a holder for an v1 attribute certificate.
     * 
     * @param tagobj the asn.1 tagged holder object.
     */
    private holder(asn1taggedobject tagobj)
    {
        switch (tagobj.gettagno())
        {
        case 0:
            basecertificateid = issuerserial.getinstance(tagobj, false);
            break;
        case 1:
            entityname = generalnames.getinstance(tagobj, false);
            break;
        default:
            throw new illegalargumentexception("unknown tag in holder");
        }
        version = 0;
    }

    /**
     * constructor for a holder for an v2 attribute certificate.
     * 
     * @param seq the asn.1 sequence.
     */
    private holder(asn1sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        for (int i = 0; i != seq.size(); i++)
        {
            asn1taggedobject tobj = asn1taggedobject.getinstance(seq
                .getobjectat(i));

            switch (tobj.gettagno())
            {
            case 0:
                basecertificateid = issuerserial.getinstance(tobj, false);
                break;
            case 1:
                entityname = generalnames.getinstance(tobj, false);
                break;
            case 2:
                objectdigestinfo = objectdigestinfo.getinstance(tobj, false);
                break;
            default:
                throw new illegalargumentexception("unknown tag in holder");
            }
        }
        version = 1;
    }

    public holder(issuerserial basecertificateid)
    {
        this(basecertificateid, v2_certificate_holder);
    }

    /**
     * constructs a holder from a issuerserial for a v1 or v2 certificate.
     * .
     * @param basecertificateid the issuerserial.
     * @param version the version of the attribute certificate. 
     */
    public holder(issuerserial basecertificateid, int version)
    {
        this.basecertificateid = basecertificateid;
        this.version = version;
    }
    
    /**
     * returns 1 for v2 attribute certificates or 0 for v1 attribute
     * certificates. 
     * @return the version of the attribute certificate.
     */
    public int getversion()
    {
        return version;
    }

    /**
     * constructs a holder with an entityname for v2 attribute certificates.
     * 
     * @param entityname the entity or subject name.
     */
    public holder(generalnames entityname)
    {
        this(entityname, v2_certificate_holder);
    }

    /**
     * constructs a holder with an entityname for v2 attribute certificates or
     * with a subjectname for v1 attribute certificates.
     * 
     * @param entityname the entity or subject name.
     * @param version the version of the attribute certificate. 
     */
    public holder(generalnames entityname, int version)
    {
        this.entityname = entityname;
        this.version = version;
    }
    
    /**
     * constructs a holder from an object digest info.
     * 
     * @param objectdigestinfo the object digest info object.
     */
    public holder(objectdigestinfo objectdigestinfo)
    {
        this.objectdigestinfo = objectdigestinfo;
    }

    public issuerserial getbasecertificateid()
    {
        return basecertificateid;
    }

    /**
     * returns the entityname for an v2 attribute certificate or the subjectname
     * for an v1 attribute certificate.
     * 
     * @return the entityname or subjectname.
     */
    public generalnames getentityname()
    {
        return entityname;
    }

    public objectdigestinfo getobjectdigestinfo()
    {
        return objectdigestinfo;
    }

    public asn1primitive toasn1primitive()
    {
        if (version == 1)
        {
            asn1encodablevector v = new asn1encodablevector();

            if (basecertificateid != null)
            {
                v.add(new dertaggedobject(false, 0, basecertificateid));
            }

            if (entityname != null)
            {
                v.add(new dertaggedobject(false, 1, entityname));
            }

            if (objectdigestinfo != null)
            {
                v.add(new dertaggedobject(false, 2, objectdigestinfo));
            }

            return new dersequence(v);
        }
        else
        {
            if (entityname != null)
            {
                return new dertaggedobject(false, 1, entityname);
            }
            else
            {
                return new dertaggedobject(false, 0, basecertificateid);
            }
        }
    }
}
