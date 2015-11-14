package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * target information extension for attributes certificates according to rfc
 * 3281.
 * 
 * <pre>
 *           sequence of targets
 * </pre>
 * 
 */
public class targetinformation
    extends asn1object
{
    private asn1sequence targets;

    /**
     * creates an instance of a targetinformation from the given object.
     * <p>
     * <code>obj</code> can be a targetinformation or a {@link asn1sequence}
     * 
     * @param obj the object.
     * @return a targetinformation instance.
     * @throws illegalargumentexception if the given object cannot be
     *             interpreted as targetinformation.
     */
    public static targetinformation getinstance(object obj)
    {
        if (obj instanceof targetinformation)
        {
            return (targetinformation)obj;
        }
        else if (obj != null)
        {
            return new targetinformation(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from a asn1sequence.
     * 
     * @param seq the asn1sequence.
     * @throws illegalargumentexception if the sequence does not contain
     *             correctly encoded targets elements.
     */
    private targetinformation(asn1sequence seq)
    {
        targets = seq;
    }

    /**
     * returns the targets in this target information extension.
     * 
     * @return returns the targets.
     */
    public targets[] gettargetsobjects()
    {
        targets[] copy = new targets[targets.size()];
        int count = 0;
        for (enumeration e = targets.getobjects(); e.hasmoreelements();)
        {
            copy[count++] = targets.getinstance(e.nextelement());
        }
        return copy;
    }

    /**
     * constructs a target information from a single targets element. 
     * according to rfc 3281 only one targets element must be produced.
     * 
     * @param targets a targets instance.
     */
    public targetinformation(targets targets)
    {
        this.targets = new dersequence(targets);
    }

    /**
     * according to rfc 3281 only one targets element must be produced. if
     * multiple targets are given they must be merged in
     * into one targets element.
     *
     * @param targets an array with {@link targets}.
     */
    public targetinformation(target[] targets)
    {
        this(new targets(targets));
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * 
     * returns:
     * 
     * <pre>
     *          sequence of targets
     * </pre>
     * 
     * <p>
     * according to rfc 3281 only one targets element must be produced. if
     * multiple targets are given in the constructor they are merged into one
     * targets element. if this was produced from a
     * {@link org.ripple.bouncycastle.asn1.asn1sequence} the encoding is kept.
     * 
     * @return a asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        return targets;
    }
}
