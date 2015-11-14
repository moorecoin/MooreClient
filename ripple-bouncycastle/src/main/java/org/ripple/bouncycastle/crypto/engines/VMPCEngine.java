package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

public class vmpcengine implements streamcipher
{
    /*
     * variables to hold the state of the vmpc engine during encryption and
     * decryption
     */
    protected byte n = 0;
    protected byte[] p = null;
    protected byte s = 0;

    protected byte[] workingiv;
    protected byte[] workingkey;

    public string getalgorithmname()
    {
        return "vmpc";
    }

    /**
     * initialise a vmpc cipher.
     * 
     * @param forencryption
     *    whether or not we are for encryption.
     * @param params
     *    the parameters required to set up the cipher.
     * @exception illegalargumentexception
     *    if the params argument is inappropriate.
     */
    public void init(boolean forencryption, cipherparameters params)
    {
        if (!(params instanceof parameterswithiv))
        {
            throw new illegalargumentexception(
                "vmpc init parameters must include an iv");
        }

        parameterswithiv ivparams = (parameterswithiv) params;
        keyparameter key = (keyparameter) ivparams.getparameters();

        if (!(ivparams.getparameters() instanceof keyparameter))
        {
            throw new illegalargumentexception(
                "vmpc init parameters must include a key");
        }

        this.workingiv = ivparams.getiv();

        if (workingiv == null || workingiv.length < 1 || workingiv.length > 768)
        {
            throw new illegalargumentexception("vmpc requires 1 to 768 bytes of iv");
        }

        this.workingkey = key.getkey();

        initkey(this.workingkey, this.workingiv);
    }

    protected void initkey(byte[] keybytes, byte[] ivbytes)
    {
        s = 0;
        p = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            p[i] = (byte) i;
        }

        for (int m = 0; m < 768; m++)
        {
            s = p[(s + p[m & 0xff] + keybytes[m % keybytes.length]) & 0xff];
            byte temp = p[m & 0xff];
            p[m & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }
        for (int m = 0; m < 768; m++)
        {
            s = p[(s + p[m & 0xff] + ivbytes[m % ivbytes.length]) & 0xff];
            byte temp = p[m & 0xff];
            p[m & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }
        n = 0;
    }

    public void processbytes(byte[] in, int inoff, int len, byte[] out,
        int outoff)
    {
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
            s = p[(s + p[n & 0xff]) & 0xff];
            byte z = p[(p[(p[s & 0xff]) & 0xff] + 1) & 0xff];
            // encryption
            byte temp = p[n & 0xff];
            p[n & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
            n = (byte) ((n + 1) & 0xff);

            // xor
            out[i + outoff] = (byte) (in[i + inoff] ^ z);
        }
    }

    public void reset()
    {
        initkey(this.workingkey, this.workingiv);
    }

    public byte returnbyte(byte in)
    {
        s = p[(s + p[n & 0xff]) & 0xff];
        byte z = p[(p[(p[s & 0xff]) & 0xff] + 1) & 0xff];
        // encryption
        byte temp = p[n & 0xff];
        p[n & 0xff] = p[s & 0xff];
        p[s & 0xff] = temp;
        n = (byte) ((n + 1) & 0xff);

        // xor
        return (byte) (in ^ z);
    }
}
