package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * a class that provides a basic desede (or triple des) engine.
 */
public class desedeengine
    extends desengine
{
    protected static final int  block_size = 8;

    private int[]               workingkey1 = null;
    private int[]               workingkey2 = null;
    private int[]               workingkey3 = null;

    private boolean             forencryption;

    /**
     * standard constructor.
     */
    public desedeengine()
    {
    }

    /**
     * initialise a desede cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           encrypting,
        cipherparameters  params)
    {
        if (!(params instanceof keyparameter))
        {
            throw new illegalargumentexception("invalid parameter passed to desede init - " + params.getclass().getname());
        }

        byte[] keymaster = ((keyparameter)params).getkey();

        if (keymaster.length != 24 && keymaster.length != 16)
        {
            throw new illegalargumentexception("key size must be 16 or 24 bytes.");
        }

        this.forencryption = encrypting;

        byte[] key1 = new byte[8];
        system.arraycopy(keymaster, 0, key1, 0, key1.length);
        workingkey1 = generateworkingkey(encrypting, key1);

        byte[] key2 = new byte[8];
        system.arraycopy(keymaster, 8, key2, 0, key2.length);
        workingkey2 = generateworkingkey(!encrypting, key2);

        if (keymaster.length == 24)
        {
            byte[] key3 = new byte[8];
            system.arraycopy(keymaster, 16, key3, 0, key3.length);
            workingkey3 = generateworkingkey(encrypting, key3);
        }
        else    // 16 byte key
        {
            workingkey3 = workingkey1;
        }
    }

    public string getalgorithmname()
    {
        return "desede";
    }

    public int getblocksize()
    {
        return block_size;
    }

    public int processblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
    {
        if (workingkey1 == null)
        {
            throw new illegalstateexception("desede engine not initialised");
        }

        if ((inoff + block_size) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + block_size) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        byte[] temp = new byte[block_size];

        if (forencryption)
        {
            desfunc(workingkey1, in, inoff, temp, 0);
            desfunc(workingkey2, temp, 0, temp, 0);
            desfunc(workingkey3, temp, 0, out, outoff);
        }
        else
        {
            desfunc(workingkey3, in, inoff, temp, 0);
            desfunc(workingkey2, temp, 0, temp, 0);
            desfunc(workingkey1, temp, 0, out, outoff);
        }

        return block_size;
    }

    public void reset()
    {
    }
}
