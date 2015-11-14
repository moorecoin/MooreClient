package org.ripple.bouncycastle.pqc.crypto.mceliece;


import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;

/**
 * this class provides a specification for the parameters of the cca2-secure
 * variants of the mceliece pkcs that are used with
 * {@link mceliecefujisakicipher}, {@link mceliecekobaraimaicipher}, and
 * {@link mceliecepointchevalcipher}.
 *
 * @see mceliecefujisakicipher
 * @see mceliecekobaraimaicipher
 * @see mceliecepointchevalcipher
 */
public class mceliececca2parameters
    extends mcelieceparameters
{


    public digest digest;


    /**
     * construct the default parameters.
     * the default message digest is sha256.
     */
    public mceliececca2parameters()
    {
        this.digest = new sha256digest();
    }

    public mceliececca2parameters(int m, int t)
    {
        super(m, t);
        this.digest = new sha256digest();
    }

    public mceliececca2parameters(digest digest)
    {
        this.digest = digest;
    }

    public digest getdigest()
    {
        return this.digest;
    }


}
