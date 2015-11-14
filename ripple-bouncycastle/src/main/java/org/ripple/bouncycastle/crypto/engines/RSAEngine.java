package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;

/**
 * this does your basic rsa algorithm.
 */
public class rsaengine
    implements asymmetricblockcipher
{
    private rsacoreengine core;

    /**
     * initialise the rsa engine.
     *
     * @param forencryption true if we are encrypting, false otherwise.
     * @param param the necessary rsa key parameters.
     */
    public void init(
        boolean             forencryption,
        cipherparameters    param)
    {
        if (core == null)
        {
            core = new rsacoreengine();
        }

        core.init(forencryption, param);
    }

    /**
     * return the maximum size for an input block to this engine.
     * for rsa this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getinputblocksize()
    {
        return core.getinputblocksize();
    }

    /**
     * return the maximum size for an output block to this engine.
     * for rsa this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getoutputblocksize()
    {
        return core.getoutputblocksize();
    }

    /**
     * process a single block using the basic rsa algorithm.
     *
     * @param in the input array.
     * @param inoff the offset into the input buffer where the data starts.
     * @param inlen the length of the data to be processed.
     * @return the result of the rsa process.
     * @exception datalengthexception the input block is too large.
     */
    public byte[] processblock(
        byte[]  in,
        int     inoff,
        int     inlen)
    {
        if (core == null)
        {
            throw new illegalstateexception("rsa engine not initialised");
        }

        return core.convertoutput(core.processblock(core.convertinput(in, inoff, inlen)));
    }
}
