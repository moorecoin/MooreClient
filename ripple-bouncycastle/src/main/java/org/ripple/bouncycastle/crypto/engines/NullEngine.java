package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;

/**
 * the no-op engine that just copies bytes through, irrespective of whether encrypting and decrypting.
 * provided for the sake of completeness.
 */
public class nullengine implements blockcipher
{
    private boolean initialised;
    protected static final int block_size = 1;
    
    /**
     * standard constructor.
     */
    public nullengine()
    {
        super();
    }

    /* (non-javadoc)
     * @see org.bouncycastle.crypto.blockcipher#init(boolean, org.bouncycastle.crypto.cipherparameters)
     */
    public void init(boolean forencryption, cipherparameters params) throws illegalargumentexception
    {
        // we don't mind any parameters that may come in
        this.initialised = true;
    }

    /* (non-javadoc)
     * @see org.bouncycastle.crypto.blockcipher#getalgorithmname()
     */
    public string getalgorithmname()
    {
        return "null";
    }

    /* (non-javadoc)
     * @see org.bouncycastle.crypto.blockcipher#getblocksize()
     */
    public int getblocksize()
    {
        return block_size;
    }

    /* (non-javadoc)
     * @see org.bouncycastle.crypto.blockcipher#processblock(byte[], int, byte[], int)
     */
    public int processblock(byte[] in, int inoff, byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {
        if (!initialised)
        {
            throw new illegalstateexception("null engine not initialised");
        }
            if ((inoff + block_size) > in.length)
            {
                throw new datalengthexception("input buffer too short");
            }

            if ((outoff + block_size) > out.length)
            {
                throw new outputlengthexception("output buffer too short");
            }
            
            for (int i = 0; i < block_size; ++i)
            {
                out[outoff + i] = in[inoff + i];
            }
            
            return block_size;
    }

    /* (non-javadoc)
     * @see org.bouncycastle.crypto.blockcipher#reset()
     */
    public void reset()
    {
        // nothing needs to be done
    }
}
