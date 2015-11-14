package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;
import org.ripple.bouncycastle.util.bigintegers;

import java.math.biginteger;
import java.security.securerandom;

/**
 * this does your basic rsa algorithm with blinding
 */
public class rsablindedengine
    implements asymmetricblockcipher
{
    private static biginteger one = biginteger.valueof(1);

    private rsacoreengine    core = new rsacoreengine();
    private rsakeyparameters key;
    private securerandom     random;

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
        core.init(forencryption, param);

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    rparam = (parameterswithrandom)param;

            key = (rsakeyparameters)rparam.getparameters();
            random = rparam.getrandom();
        }
        else
        {
            key = (rsakeyparameters)param;
            random = new securerandom();
        }
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
        if (key == null)
        {
            throw new illegalstateexception("rsa engine not initialised");
        }

        biginteger input = core.convertinput(in, inoff, inlen);

        biginteger result;
        if (key instanceof rsaprivatecrtkeyparameters)
        {
            rsaprivatecrtkeyparameters k = (rsaprivatecrtkeyparameters)key;

            biginteger e = k.getpublicexponent();
            if (e != null)   // can't do blinding without a public exponent
            {
                biginteger m = k.getmodulus();
                biginteger r = bigintegers.createrandominrange(one, m.subtract(one), random);

                biginteger blindedinput = r.modpow(e, m).multiply(input).mod(m);
                biginteger blindedresult = core.processblock(blindedinput);

                biginteger rinv = r.modinverse(m);
                result = blindedresult.multiply(rinv).mod(m);
            }
            else
            {
                result = core.processblock(input);
            }
        }
        else
        {
            result = core.processblock(input);
        }

        return core.convertoutput(result);
    }
}
