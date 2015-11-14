package org.ripple.bouncycastle.crypto;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

/**
 * a holding class for public/private parameter pairs.
 */
public class asymmetriccipherkeypair
{
    private asymmetrickeyparameter    publicparam;
    private asymmetrickeyparameter    privateparam;

    /**
     * basic constructor.
     *
     * @param publicparam a public key parameters object.
     * @param privateparam the corresponding private key parameters.
     */
    public asymmetriccipherkeypair(
        asymmetrickeyparameter    publicparam,
        asymmetrickeyparameter    privateparam)
    {
        this.publicparam = publicparam;
        this.privateparam = privateparam;
    }

    /**
     * basic constructor.
     *
     * @param publicparam a public key parameters object.
     * @param privateparam the corresponding private key parameters.
     * @deprecated use asymmetrickeyparameter
     */
    public asymmetriccipherkeypair(
        cipherparameters    publicparam,
        cipherparameters    privateparam)
    {
        this.publicparam = (asymmetrickeyparameter)publicparam;
        this.privateparam = (asymmetrickeyparameter)privateparam;
    }

    /**
     * return the public key parameters.
     *
     * @return the public key parameters.
     */
    public asymmetrickeyparameter getpublic()
    {
        return publicparam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public asymmetrickeyparameter getprivate()
    {
        return privateparam;
    }
}
