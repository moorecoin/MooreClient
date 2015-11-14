package org.ripple.bouncycastle.crypto.signers;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.util.arrays;

public class genericsigner
    implements signer
{
    private final asymmetricblockcipher engine;
    private final digest digest;
    private boolean forsigning;

    public genericsigner(
        asymmetricblockcipher engine,
        digest                digest)
    {
        this.engine = engine;
        this.digest = digest;
    }

    /**
     * initialise the signer for signing or verification.
     *
     * @param forsigning
     *            true if for signing, false otherwise
     * @param parameters
     *            necessary parameters.
     */
    public void init(
        boolean          forsigning,
        cipherparameters parameters)
    {
        this.forsigning = forsigning;
        asymmetrickeyparameter k;

        if (parameters instanceof parameterswithrandom)
        {
            k = (asymmetrickeyparameter)((parameterswithrandom)parameters).getparameters();
        }
        else
        {
            k = (asymmetrickeyparameter)parameters;
        }

        if (forsigning && !k.isprivate())
        {
            throw new illegalargumentexception("signing requires private key");
        }

        if (!forsigning && k.isprivate())
        {
            throw new illegalargumentexception("verification requires public key");
        }

        reset();

        engine.init(forsigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  input,
        int     inoff,
        int     length)
    {
        digest.update(input, inoff, length);
    }

    /**
     * generate a signature for the message we've been loaded with using the key
     * we were initialised with.
     */
    public byte[] generatesignature()
        throws cryptoexception, datalengthexception
    {
        if (!forsigning)
        {
            throw new illegalstateexception("genericsigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);

        return engine.processblock(hash, 0, hash.length);
    }

    /**
     * return true if the internal state represents the signature described in
     * the passed in array.
     */
    public boolean verifysignature(
        byte[] signature)
    {
        if (forsigning)
        {
            throw new illegalstateexception("genericsigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);

        try
        {
            byte[] sig = engine.processblock(signature, 0, signature.length);

            return arrays.constanttimeareequal(sig, hash);
        }
        catch (exception e)
        {
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }
}
