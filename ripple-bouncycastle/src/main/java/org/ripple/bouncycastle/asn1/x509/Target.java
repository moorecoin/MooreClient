package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * target structure used in target information extension for attribute
 * certificates from rfc 3281.
 * 
 * <pre>
 *     target  ::= choice {
 *       targetname          [0] generalname,
 *       targetgroup         [1] generalname,
 *       targetcert          [2] targetcert
 *     }
 * </pre>
 * 
 * <p>
 * the targetcert field is currently not supported and must not be used
 * according to rfc 3281.
 */
public class target
    extends asn1object
    implements asn1choice
{
    public static final int targetname = 0;
    public static final int targetgroup = 1;

    private generalname targname;
    private generalname targgroup;

    /**
     * creates an instance of a target from the given object.
     * <p>
     * <code>obj</code> can be a target or a {@link asn1taggedobject}
     * 
     * @param obj the object.
     * @return a target instance.
     * @throws illegalargumentexception if the given object cannot be
     *             interpreted as target.
     */
    public static target getinstance(object obj)
    {
        if (obj == null || obj instanceof target)
        {
            return (target) obj;
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new target((asn1taggedobject)obj);
        }

        throw new illegalargumentexception("unknown object in factory: "
            + obj.getclass());
    }

    /**
     * constructor from asn1taggedobject.
     * 
     * @param tagobj the tagged object.
     * @throws illegalargumentexception if the encoding is wrong.
     */
    private target(asn1taggedobject tagobj)
    {
        switch (tagobj.gettagno())
        {
        case targetname:     // generalname is already a choice so explicit
            targname = generalname.getinstance(tagobj, true);
            break;
        case targetgroup:
            targgroup = generalname.getinstance(tagobj, true);
            break;
        default:
            throw new illegalargumentexception("unknown tag: " + tagobj.gettagno());
        }
    }

    /**
     * constructor from given details.
     * <p>
     * exactly one of the parameters must be not <code>null</code>.
     *
     * @param type the choice type to apply to the name.
     * @param name the general name.
     * @throws illegalargumentexception if type is invalid.
     */
    public target(int type, generalname name)
    {
        this(new dertaggedobject(type, name));
    }

    /**
     * @return returns the targetgroup.
     */
    public generalname gettargetgroup()
    {
        return targgroup;
    }

    /**
     * @return returns the targetname.
     */
    public generalname gettargetname()
    {
        return targname;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * 
     * returns:
     * 
     * <pre>
     *     target  ::= choice {
     *       targetname          [0] generalname,
     *       targetgroup         [1] generalname,
     *       targetcert          [2] targetcert
     *     }
     * </pre>
     * 
     * @return a asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        // generalname is a choice already so most be explicitly tagged
        if (targname != null)
        {
            return new dertaggedobject(true, 0, targname);
        }
        else
        {
            return new dertaggedobject(true, 1, targgroup);
        }
    }
}
