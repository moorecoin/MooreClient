package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implements the segmented integer counter (sic) mode on top of a simple
 * block cipher. this mode is also known as ctr mode.
 */
public class sicblockcipher
    implements blockcipher
{
    private final blockcipher     cipher;
    private final int             blocksize;
    
    private byte[]          iv;
    private byte[]          counter;
    private byte[]          counterout;


    /**
     * basic constructor.
     *
     * @param c the block cipher to be used.
     */
    public sicblockcipher(blockcipher c)
    {
        this.cipher = c;
        this.blocksize = cipher.getblocksize();
        this.iv = new byte[blocksize];
        this.counter = new byte[blocksize];
        this.counterout = new byte[blocksize];
    }


    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    public blockcipher getunderlyingcipher()
    {
        return cipher;
    }


    public void init(
        boolean             forencryption, //ignored by this ctr mode
        cipherparameters    params)
        throws illegalargumentexception
    {
        if (params instanceof parameterswithiv)
        {
          parameterswithiv ivparam = (parameterswithiv)params;
          byte[]           iv      = ivparam.getiv();
          system.arraycopy(iv, 0, iv, 0, iv.length);

          reset();

          // if null it's an iv changed only.
          if (ivparam.getparameters() != null)
          {
            cipher.init(true, ivparam.getparameters());
          }
        }
        else
        {
            throw new illegalargumentexception("sic mode requires parameterswithiv");
        }
    }

    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/sic";
    }

    public int getblocksize()
    {
        return cipher.getblocksize();
    }


    public int processblock(byte[] in, int inoff, byte[] out, int outoff)
          throws datalengthexception, illegalstateexception
    {
        cipher.processblock(counter, 0, counterout, 0);

        //
        // xor the counterout with the plaintext producing the cipher text
        //
        for (int i = 0; i < counterout.length; i++)
        {
          out[outoff + i] = (byte)(counterout[i] ^ in[inoff + i]);
        }

        // increment counter by 1.
        for (int i = counter.length - 1; i >= 0 && ++counter[i] == 0; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }

        return counter.length;
    }


    public void reset()
    {
        system.arraycopy(iv, 0, counter, 0, counter.length);
        cipher.reset();
    }
}
