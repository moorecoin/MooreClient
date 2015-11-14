package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a padder that adds iso10126-2 padding to a block.
 */
public class iso10126d2padding
    implements blockcipherpadding
{
    securerandom    random;

    /**
     * initialise the padder.
     *
     * @param random a securerandom if available.
     */
    public void init(securerandom random)
        throws illegalargumentexception
    {
        if (random != null)
        {
            this.random = random;
        }
        else
        {
            this.random = new securerandom();
        }
    }

    /**
     * return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public string getpaddingname()
    {
        return "iso10126-2";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    public int addpadding(
        byte[]  in,
        int     inoff)
    {
        byte code = (byte)(in.length - inoff);

        while (inoff < (in.length - 1))
        {
            in[inoff] = (byte)random.nextint();
            inoff++;
        }

        in[inoff] = code;

        return code;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padcount(byte[] in)
        throws invalidciphertextexception
    {
        int count = in[in.length - 1] & 0xff;

        if (count > in.length)
        {
            throw new invalidciphertextexception("pad block corrupted");
        }

        return count;
    }
}
