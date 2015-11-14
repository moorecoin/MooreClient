package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1enumerated;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * objectdigestinfo asn.1 structure used in v2 attribute certificates.
 * 
 * <pre>
 *  
 *    objectdigestinfo ::= sequence {
 *         digestedobjecttype  enumerated {
 *                 publickey            (0),
 *                 publickeycert        (1),
 *                 otherobjecttypes     (2) },
 *                         -- otherobjecttypes must not
 *                         -- be used in this profile
 *         otherobjecttypeid   object identifier optional,
 *         digestalgorithm     algorithmidentifier,
 *         objectdigest        bit string
 *    }
 *   
 * </pre>
 * 
 */
public class objectdigestinfo
    extends asn1object
{
    /**
     * the public key is hashed.
     */
    public final static int publickey = 0;

    /**
     * the public key certificate is hashed.
     */
    public final static int publickeycert = 1;

    /**
     * an other object is hashed.
     */
    public final static int otherobjectdigest = 2;

    asn1enumerated digestedobjecttype;

    asn1objectidentifier otherobjecttypeid;

    algorithmidentifier digestalgorithm;

    derbitstring objectdigest;

    public static objectdigestinfo getinstance(
        object obj)
    {
        if (obj instanceof objectdigestinfo)
        {
            return (objectdigestinfo)obj;
        }

        if (obj != null)
        {
            return new objectdigestinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static objectdigestinfo getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * constructor from given details.
     * <p>
     * if <code>digestedobjecttype</code> is not {@link #publickeycert} or
     * {@link #publickey} <code>otherobjecttypeid</code> must be given,
     * otherwise it is ignored.
     * 
     * @param digestedobjecttype the digest object type.
     * @param otherobjecttypeid the object type id for
     *            <code>otherobjectdigest</code>.
     * @param digestalgorithm the algorithm identifier for the hash.
     * @param objectdigest the hash value.
     */
    public objectdigestinfo(
        int digestedobjecttype,
        asn1objectidentifier otherobjecttypeid,
        algorithmidentifier digestalgorithm,
        byte[] objectdigest)
    {
        this.digestedobjecttype = new asn1enumerated(digestedobjecttype);
        if (digestedobjecttype == otherobjectdigest)
        {
            this.otherobjecttypeid = otherobjecttypeid;
        }

        this.digestalgorithm = digestalgorithm;
        this.objectdigest = new derbitstring(objectdigest);
    }

    private objectdigestinfo(
        asn1sequence seq)
    {
        if (seq.size() > 4 || seq.size() < 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        digestedobjecttype = asn1enumerated.getinstance(seq.getobjectat(0));

        int offset = 0;

        if (seq.size() == 4)
        {
            otherobjecttypeid = asn1objectidentifier.getinstance(seq.getobjectat(1));
            offset++;
        }

        digestalgorithm = algorithmidentifier.getinstance(seq.getobjectat(1 + offset));

        objectdigest = derbitstring.getinstance(seq.getobjectat(2 + offset));
    }

    public asn1enumerated getdigestedobjecttype()
    {
        return digestedobjecttype;
    }

    public asn1objectidentifier getotherobjecttypeid()
    {
        return otherobjecttypeid;
    }

    public algorithmidentifier getdigestalgorithm()
    {
        return digestalgorithm;
    }

    public derbitstring getobjectdigest()
    {
        return objectdigest;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * 
     * <pre>
     *  
     *    objectdigestinfo ::= sequence {
     *         digestedobjecttype  enumerated {
     *                 publickey            (0),
     *                 publickeycert        (1),
     *                 otherobjecttypes     (2) },
     *                         -- otherobjecttypes must not
     *                         -- be used in this profile
     *         otherobjecttypeid   object identifier optional,
     *         digestalgorithm     algorithmidentifier,
     *         objectdigest        bit string
     *    }
     *   
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(digestedobjecttype);

        if (otherobjecttypeid != null)
        {
            v.add(otherobjecttypeid);
        }

        v.add(digestalgorithm);
        v.add(objectdigest);

        return new dersequence(v);
    }
}
