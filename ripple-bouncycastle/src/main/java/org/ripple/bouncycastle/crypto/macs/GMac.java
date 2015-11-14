package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * the gmac specialisation of galois/counter mode (gcm) detailed in nist special publication
 * 800-38d.
 * <p>
 * gmac is an invocation of the gcm mode where no data is encrypted (i.e. all input data to the mac
 * is processed as additional authenticated data with the underlying gcm block cipher).
 */
public class gmac implements mac
{
    private final gcmblockcipher cipher;
    private final int macsizebits;

    /**
     * creates a gmac based on the operation of a block cipher in gcm mode.
     * <p/>
     * this will produce an authentication code the length of the block size of the cipher.
     * 
     * @param cipher
     *            the cipher to be used in gcm mode to generate the mac.
     */
    public gmac(final gcmblockcipher cipher)
    {
        // use of this confused flow analyser in some earlier jdks
        this.cipher = cipher;
        this.macsizebits = 128;
    }

    /**
     * creates a gmac based on the operation of a 128 bit block cipher in gcm mode.
     * 
     * @param macsizebits
     *            the mac size to generate, in bits. must be a multiple of 8 and >= 96 and <= 128.
     * @param cipher
     *            the cipher to be used in gcm mode to generate the mac.
     */
    public gmac(final gcmblockcipher cipher, final int macsizebits)
    {
        this.cipher = cipher;
        this.macsizebits = macsizebits;
    }

    /**
     * initialises the gmac - requires a {@link parameterswithiv} providing a {@link keyparameter}
     * and a nonce.
     */
    public void init(final cipherparameters params) throws illegalargumentexception
    {
        if (params instanceof parameterswithiv)
        {
            final parameterswithiv param = (parameterswithiv)params;

            final byte[] iv = param.getiv();
            final keyparameter keyparam = (keyparameter)param.getparameters();

            // gcm is always operated in encrypt mode to calculate mac
            cipher.init(true, new aeadparameters(keyparam, macsizebits, iv));
        }
        else
        {
            throw new illegalargumentexception("gmac requires parameterswithiv");
        }
    }

    public string getalgorithmname()
    {
        return cipher.getunderlyingcipher().getalgorithmname() + "-gmac";
    }

    public int getmacsize()
    {
        return macsizebits / 8;
    }

    public void update(byte in) throws illegalstateexception
    {
        cipher.processaadbyte(in);
    }

    public void update(byte[] in, int inoff, int len)
        throws datalengthexception, illegalstateexception
    {
        cipher.processaadbytes(in, inoff, len);
    }

    public int dofinal(byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {
        try
        {
            return cipher.dofinal(out, outoff);
        }
        catch (invalidciphertextexception e)
        {
            // impossible in encrypt mode
            throw new illegalstateexception(e.tostring());
        }
    }

    public void reset()
    {
        cipher.reset();
    }
}
