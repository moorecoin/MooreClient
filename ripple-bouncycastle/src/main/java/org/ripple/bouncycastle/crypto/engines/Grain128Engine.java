package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implementation of martin hell's, thomas johansson's and willi meier's stream
 * cipher, grain-128.
 */
public class grain128engine
    implements streamcipher
{

    /**
     * constants
     */
    private static final int state_size = 4;

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
    private int index = 4;

    private boolean initialised = false;

    public string getalgorithmname()
    {
        return "grain-128";
    }

    /**
     * initialize a grain-128 cipher.
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
                "grain-128 init parameters must include an iv");
        }

        parameterswithiv ivparams = (parameterswithiv)params;

        byte[] iv = ivparams.getiv();

        if (iv == null || iv.length != 12)
        {
            throw new illegalargumentexception(
                "grain-128  requires exactly 12 bytes of iv");
        }

        if (!(ivparams.getparameters() instanceof keyparameter))
        {
            throw new illegalargumentexception(
                "grain-128 init parameters must include a key");
        }

        keyparameter key = (keyparameter)ivparams.getparameters();

        /**
         * initialize variables.
         */
        workingiv = new byte[key.getkey().length];
        workingkey = new byte[key.getkey().length];
        lfsr = new int[state_size];
        nfsr = new int[state_size];
        out = new byte[4];

        system.arraycopy(iv, 0, workingiv, 0, iv.length);
        system.arraycopy(key.getkey(), 0, workingkey, 0, key.getkey().length);

        setkey(workingkey, workingiv);
        initgrain();
    }

    /**
     * 256 clocks initialization phase.
     */
    private void initgrain()
    {
        for (int i = 0; i < 8; i++)
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
        int b3 = nfsr[0] >>> 3 | nfsr[1] << 29;
        int b11 = nfsr[0] >>> 11 | nfsr[1] << 21;
        int b13 = nfsr[0] >>> 13 | nfsr[1] << 19;
        int b17 = nfsr[0] >>> 17 | nfsr[1] << 15;
        int b18 = nfsr[0] >>> 18 | nfsr[1] << 14;
        int b26 = nfsr[0] >>> 26 | nfsr[1] << 6;
        int b27 = nfsr[0] >>> 27 | nfsr[1] << 5;
        int b40 = nfsr[1] >>> 8 | nfsr[2] << 24;
        int b48 = nfsr[1] >>> 16 | nfsr[2] << 16;
        int b56 = nfsr[1] >>> 24 | nfsr[2] << 8;
        int b59 = nfsr[1] >>> 27 | nfsr[2] << 5;
        int b61 = nfsr[1] >>> 29 | nfsr[2] << 3;
        int b65 = nfsr[2] >>> 1 | nfsr[3] << 31;
        int b67 = nfsr[2] >>> 3 | nfsr[3] << 29;
        int b68 = nfsr[2] >>> 4 | nfsr[3] << 28;
        int b84 = nfsr[2] >>> 20 | nfsr[3] << 12;
        int b91 = nfsr[2] >>> 27 | nfsr[3] << 5;
        int b96 = nfsr[3];

        return b0 ^ b26 ^ b56 ^ b91 ^ b96 ^ b3 & b67 ^ b11 & b13 ^ b17 & b18
            ^ b27 & b59 ^ b40 & b48 ^ b61 & b65 ^ b68 & b84;
    }

    /**
     * get output from linear function f(x).
     *
     * @return output from lfsr.
     */
    private int getoutputlfsr()
    {
        int s0 = lfsr[0];
        int s7 = lfsr[0] >>> 7 | lfsr[1] << 25;
        int s38 = lfsr[1] >>> 6 | lfsr[2] << 26;
        int s70 = lfsr[2] >>> 6 | lfsr[3] << 26;
        int s81 = lfsr[2] >>> 17 | lfsr[3] << 15;
        int s96 = lfsr[3];

        return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
    }

    /**
     * get output from output function h(x).
     *
     * @return output from h(x).
     */
    private int getoutput()
    {
        int b2 = nfsr[0] >>> 2 | nfsr[1] << 30;
        int b12 = nfsr[0] >>> 12 | nfsr[1] << 20;
        int b15 = nfsr[0] >>> 15 | nfsr[1] << 17;
        int b36 = nfsr[1] >>> 4 | nfsr[2] << 28;
        int b45 = nfsr[1] >>> 13 | nfsr[2] << 19;
        int b64 = nfsr[2];
        int b73 = nfsr[2] >>> 9 | nfsr[3] << 23;
        int b89 = nfsr[2] >>> 25 | nfsr[3] << 7;
        int b95 = nfsr[2] >>> 31 | nfsr[3] << 1;
        int s8 = lfsr[0] >>> 8 | lfsr[1] << 24;
        int s13 = lfsr[0] >>> 13 | lfsr[1] << 19;
        int s20 = lfsr[0] >>> 20 | lfsr[1] << 12;
        int s42 = lfsr[1] >>> 10 | lfsr[2] << 22;
        int s60 = lfsr[1] >>> 28 | lfsr[2] << 4;
        int s79 = lfsr[2] >>> 15 | lfsr[3] << 17;
        int s93 = lfsr[2] >>> 29 | lfsr[3] << 3;
        int s95 = lfsr[2] >>> 31 | lfsr[3] << 1;

        return b12 & s8 ^ s13 & s20 ^ b95 & s42 ^ s60 & s79 ^ b12 & b95 & s95 ^ s93
            ^ b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89;
    }

    /**
     * shift array 32 bits and add val to index.length - 1.
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
        array[3] = val;

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
        ivbytes[12] = (byte)0xff;
        ivbytes[13] = (byte)0xff;
        ivbytes[14] = (byte)0xff;
        ivbytes[15] = (byte)0xff;
        workingkey = keybytes;
        workingiv = ivbytes;

        /**
         * load nfsr and lfsr
         */
        int j = 0;
        for (int i = 0; i < nfsr.length; i++)
        {
            nfsr[i] = ((workingkey[j + 3]) << 24) | ((workingkey[j + 2]) << 16)
                & 0x00ff0000 | ((workingkey[j + 1]) << 8) & 0x0000ff00
                | ((workingkey[j]) & 0x000000ff);

            lfsr[i] = ((workingiv[j + 3]) << 24) | ((workingiv[j + 2]) << 16)
                & 0x00ff0000 | ((workingiv[j + 1]) << 8) & 0x0000ff00
                | ((workingiv[j]) & 0x000000ff);
            j += 4;
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
        index = 4;
        setkey(workingkey, workingiv);
        initgrain();
    }

    /**
     * run grain one round(i.e. 32 bits).
     */
    private void oneround()
    {
        output = getoutput();
        out[0] = (byte)output;
        out[1] = (byte)(output >> 8);
        out[2] = (byte)(output >> 16);
        out[3] = (byte)(output >> 24);

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
        if (index > 3)
        {
            oneround();
            index = 0;
        }
        return out[index++];
    }
}
