package org.ripple.bouncycastle.util;

/**
 * exception to be thrown on a failure to reset an object implementing memoable.
 * <p>
 * the exception extends classcastexception to enable users to have a single handling case,
 * only introducing specific handling of this one if required.
 * </p>
 */
public class memoableresetexception
    extends classcastexception
{
    /**
     * basic constructor.
     *
     * @param msg message to be associated with this exception.
     */
    public memoableresetexception(string msg)
    {
        super(msg);
    }
}
