package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implementation of martin hell's, thomas johansson's and willi meier's stream
 * cipher, grain v1.
 */
public class grainv1engine
    implements streamcipher
{

    /**
     * constants
     */
    private static final int state_size = 5;

    /**
     * variables to hold the state of the engine during encryption and
     * decryption
     */
    private byte[] workingkey;
    private byte[] workingiv;
    private byte[] out;
    private int[] lfsr;
    private int[] nfsr;
    private int output;
    private int index = 2;

    private boolean initialised = false;

    public string getalgorithmname()
    {
        return "grain v1";
    }

    /**
     * initialize a grain v1 cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params        the parameters required to set up the cipher.
     * @throws illegalargumentexception if the params argument is inappropriate.
     */
    public void init(boolean forencryption, cipherparameters params)
        throws illegalargumentexception
    {
        /**
         * grain encryption and decryption is completely symmetrical, so the
         * 'forencryption' is irrelevant.
         */
        if (!(params instanceof parameterswithiv))
        {
            throw new illegalargumentexception(
                "grain v1 init parameters must include an iv");
        }

        parameterswithiv ivparams = (parameterswithiv)params;

        byte[] iv = ivparams.getiv();

        if (iv == null || iv.length != 8)
        {
            throw new illegalargumentexception(
                "grain v1 requires exactly 8 bytes of iv");
        }

        if (!(ivparams.getparameters() instanceof keyparameter))
        {
            throw new illegalargumentexception(
                "grain v1 init parameters must include a key");
        }

        keyparameter key = (keyparameter)ivparams.getparameters();

        /**
         * initialize variables.
         */
        workingiv = new byte[key.getkey().length];
        workingkey = new byte[key.getkey().length];
        lfsr = new int[state_size];
        nfsr = new int[state_size];
        out = new byte[2];

        system.arraycopy(iv, 0, workingiv, 0, iv.length);
        system.arraycopy(key.getkey(), 0, workingkey, 0, key.getkey().length);

        setkey(workingkey, workingiv);
        initgrain();
    }

    /**
     * 160 clocks initialization phase.
     */
    private void initgrain()
    {
        for (int i = 0; i < 10; i++)
        {
            output = getoutput();
            nfsr = shift(nfsr, getoutputnfsr() ^ lfsr[0] ^ output);
            lfsr = shift(lfsr, getoutputlfsr() ^ output);
        }
        initialised = true;
    }

    /**
     * get output from non-linear function g(x).
     *
     * @return output from nfsr.
     */
    private int getoutputnfsr()
    {
        int b0 = nfsr[0];
        int b9 = nfsr[0] >>> 9 | nfsr[1] << 7;
        int b14 = nfsr[0] >>> 14 | nfsr[1] << 2;
        int b15 = nfsr[0] >>> 15 | nfsr[1] << 1;
        int b21 = nfsr[1] >>> 5 | nfsr[2] << 11;
        int b28 = nfsr[1] >>> 12 | nfsr[2] << 4;
        int b33 = nfsr[2] >>> 1 | nfsr[3] << 15;
        int b37 = nfsr[2] >>> 5 | nfsr[3] << 11;
        int b45 = nfsr[2] >>> 13 | nfsr[3] << 3;
        int b52 = nfsr[3] >>> 4 | nfsr[4] << 12;
        int b60 = nfsr[3] >>> 12 | nfsr[4] << 4;
        int b62 = nfsr[3] >>> 14 | nfsr[4] << 2;
        int b63 = nfsr[3] >>> 15 | nfsr[4] << 1;

        return (b62 ^ b60 ^ b52 ^ b45 ^ b37 ^ b33 ^ b28 ^ b21 ^ b14
            ^ b9 ^ b0 ^ b63 & b60 ^ b37 & b33 ^ b15 & b9 ^ b60 & b52 & b45
            ^ b33 & b28 & b21 ^ b63 & b45 & b28 & b9 ^ b60 & b52 & b37
            & b33 ^ b63 & b60 & b21 & b15 ^ b63 & b60 & b52 & b45 & b37
            ^ b33 & b28 & b21 & b15 & b9 ^ b52 & b45 & b37 & b33 & b28
            & b21) & 0x0000ffff;
    }

    /**
     * get output from linear function f(x).
     *
     * @return output from lfsr.
     */
    private int getoutputlfsr()
    {
        int s0 = lfsr[0];
        int s13 = lfsr[0] >>> 13 | lfsr[1] << 3;
        int s23 = lfsr[1] >>> 7 | lfsr[2] << 9;
        int s38 = lfsr[2] >>> 6 | lfsr[3] << 10;
        int s51 = lfsr[3] >>> 3 | lfsr[4] << 13;
        int s62 = lfsr[3] >>> 14 | lfsr[4] << 2;

        return (s0 ^ s13 ^ s23 ^ s38 ^ s51 ^ s62) & 0x0000ffff;
    }

    /**
     * get output from output function h(x).
     *
     * @return output from h(x).
     */
    private int getoutput()
    {
        int b1 = nfsr[0] >>> 1 | nfsr[1] << 15;
        int b2 = nfsr[0] >>> 2 | nfsr[1] << 14;
        int b4 = nfsr[0] >>> 4 | nfsr[1] << 12;
        int b10 = nfsr[0] >>> 10 | nfsr[1] << 6;
        int b31 = nfsr[1] >>> 15 | nfsr[2] << 1;
        int b43 = nfsr[2] >>> 11 | nfsr[3] << 5;
        int b56 = nfsr[3] >>> 8 | nfsr[4] << 8;
        int b63 = nfsr[3] >>> 15 | nfsr[4] << 1;
        int s3 = lfsr[0] >>> 3 | lfsr[1] << 13;
        int s25 = lfsr[1] >>> 9 | lfsr[2] << 7;
        int s46 = lfsr[2] >>> 14 | lfsr[3] << 2;
        int s64 = lfsr[4];

        return (s25 ^ b63 ^ s3 & s64 ^ s46 & s64 ^ s64 & b63 ^ s3
            & s25 & s46 ^ s3 & s46 & s64 ^ s3 & s46 & b63 ^ s25 & s46 & b63 ^ s46
            & s64 & b63 ^ b1 ^ b2 ^ b4 ^ b10 ^ b31 ^ b43 ^ b56) & 0x0000ffff;
    }

    /**
     * shift array 16 bits and add val to index.length - 1.
     *
     * @param array the array to shift.
     * @param val   the value to shift in.
     * @return the shifted array with val added to index.length - 1.
     */
    private int[] shift(int[] array, int val)
    {
        array[0] = array[1];
        array[1] = array[2];
        array[2] = array[3];
        array[3] = array[4];
        array[4] = val;

        return array;
    }

    /**
     * set keys, reset cipher.
     *
     * @param keybytes the key.
     * @param ivbytes  the iv.
     */
    private void setkey(byte[] keybytes, byte[] ivbytes)
    {
        ivbytes[8] = (byte)0xff;
        ivbytes[9] = (byte)0xff;
        workingkey = keybytes;
        workingiv = ivbytes;

        /**
         * load nfsr and lfsr
         */
        int j = 0;
        for (int i = 0; i < nfsr.length; i++)
        {
            nfsr[i] = (workingkey[j + 1] << 8 | workingkey[j] & 0xff) & 0x0000ffff;
            lfsr[i] = (workingiv[j + 1] << 8 | workingiv[j] & 0xff) & 0x0000ffff;
            j += 2;
        }
    }

    public void processbytes(byte[] in, int inoff, int len, byte[] out,
                             int outoff)
        throws datalengthexception
    {
        if (!initialised)
        {
            throw new illegalstateexception(getalgorithmname()
                + " not initialised");
        }

        if ((inoff + len) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + len) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        for (int i = 0; i < len; i++)
        {
            out[outoff + i] = (byte)(in[inoff + i] ^ getkeystream());
        }
    }

    public void reset()
    {
        index = 2;
        setkey(workingkey, workingiv);
        initgrain();
    }

    /**
     * run grain one round(i.e. 16 bits).
     */
    private void oneround()
    {
        output = getoutput();
        out[0] = (byte)output;
        out[1] = (byte)(output >> 8);

        nfsr = shift(nfsr, getoutputnfsr() ^ lfsr[0]);
        lfsr = shift(lfsr, getoutputlfsr());
    }

    public byte returnbyte(byte in)
    {
        if (!initialised)
        {
            throw new illegalstateexception(getalgorithmname()
                + " not initialised");
        }
        return (byte)(in ^ getkeystream());
    }

    private byte getkeystream()
    {
        if (index > 1)
        {
            oneround();
            index = 0;
        }
        return out[index++];
    }
}