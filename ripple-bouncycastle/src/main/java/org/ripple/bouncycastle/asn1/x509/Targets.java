package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * targets structure used in target information extension for attribute
 * certificates from rfc 3281.
 * 
 * <pre>
 *            targets ::= sequence of target
 *           
 *            target  ::= choice {
 *              targetname          [0] generalname,
 *              targetgroup         [1] generalname,
 *              targetcert          [2] targetcert
 *            }
 *           
 *            targetcert  ::= sequence {
 *              targetcertificate    issuerserial,
 *              targetname           generalname optional,
 *              certdigestinfo       objectdigestinfo optional
 *            }
 * </pre>
 * 
 * @see org.ripple.bouncycastle.asn1.x509.target
 * @see org.ripple.bouncycastle.asn1.x509.targetinformation
 */
public class targets
    extends asn1object
{
    private asn1sequence targets;

    /**
     * creates an instance of a targets from the given object.
     * <p>
     * <code>obj</code> can be a targets or a {@link asn1sequence}
     * 
     * @param obj the object.
     * @return a targets instance.
     * @throws illegalargumentexception if the given object cannot be
     *             interpreted as target.
     */
    public static targets getinstance(object obj)
    {
        if (obj instanceof targets)
        {
            return (targets)obj;
        }
        else if (obj != null)
        {
            return new targets(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from asn1sequence.
     * 
     * @param targets the asn.1 sequence.
     * @throws illegalargumentexception if the contents of the sequence are
     *             invalid.
     */
    private targets(asn1sequence targets)
    {
        this.targets = targets;
    }

    /**
     * constructor from given targets.
     * <p>
     * the vector is copied.
     * 
     * @param targets a <code>vector</code> of {@link target}s.
     * @see target
     * @throws illegalargumentexception if the vector contains not only targets.
     */
    public targets(target[] targets)
    {
        this.targets = new dersequence(targets);
    }

    /**
     * returns the targets in a <code>vector</code>.
     * <p>
     * the vector is cloned before it is returned.
     * 
     * @return returns the targets.
     */
    public target[] gettargets()
    {
        target[] targs = new target[targets.size()];
        int count = 0;
        for (enumeration e = targets.getobjects(); e.hasmoreelements();)
        {
            targs[count++] = target.getinstance(e.nextelement());
        }
        return targs;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * 
     * returns:
     * 
     * <pre>
     *            targets ::= sequence of target
     * </pre>
     * 
     * @return a asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        return targets;
    }
}
