package org.ripple.bouncycastle.pqc.crypto;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;


/**
 * implements the sign and verify functions for a signature scheme which can use a hash function.
 */
public class digestingmessagesigner
    implements signer
{
    private final digest messdigest;
    private final messagesigner messsigner;
    private boolean forsigning;

    public digestingmessagesigner(messagesigner messsigner, digest messdigest)
    {
        this.messsigner = messsigner;
        this.messdigest = messdigest;
    }

    public void init(boolean forsigning,
                     cipherparameters param)
    {

        this.forsigning = forsigning;
        asymmetrickeyparameter k;

        if (param instanceof parameterswithrandom)
        {
            k = (asymmetrickeyparameter)((parameterswithrandom)param).getparameters();
        }
        else
        {
            k = (asymmetrickeyparameter)param;
        }

        if (forsigning && !k.isprivate())
        {
            throw new illegalargumentexception("signing requires private key.");
        }

        if (!forsigning && k.isprivate())
        {
            throw new illegalargumentexception("verification requires public key.");
        }

        reset();

        messsigner.init(forsigning, param);
    }


    /**
     * this function signs the message that has been updated, making use of the
     * private key.
     *
     * @return the signature of the message.
     */
    public byte[] generatesignature()
    {
        if (!forsigning)
        {
            throw new illegalstateexception("rainbowdigestsigner not initialised for signature generation.");
        }

        byte[] hash = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hash, 0);

        return messsigner.generatesignature(hash);
    }

    /**
     * this function verifies the signature of the message that has been
     * updated, with the aid of the public key.
     *
     * @param signature the signature of the message is given as a byte array.
     * @return true if the signature has been verified, false otherwise.
     */
    public boolean verify(byte[] signature)
    {
        if (forsigning)
        {
            throw new illegalstateexception("rainbowdigestsigner not initialised for verification");
        }

        byte[] hash = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hash, 0);

        return messsigner.verifysignature(hash, signature);

    }

    public void update(byte b)
    {
        messdigest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        messdigest.update(in, off, len);
    }

    public void reset()
    {
        messdigest.reset();
    }

    public boolean verifysignature(byte[] signature)
    {
        return this.verify(signature);
    }
}
