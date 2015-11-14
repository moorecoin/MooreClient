package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a padder that adds x9.23 padding to a block - if a securerandom is
 * passed in random padding is assumed, otherwise padding with zeros is used.
 */
public class x923padding
    implements blockcipherpadding
{
    securerandom    random = null;

    /**
     * initialise the padder.
     *
     * @param random a securerandom if one is available.
     */
    public void init(securerandom random)
        throws illegalargumentexception
    {
        this.random = random;
    }

    /**
     * return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public string getpaddingname()
    {
        return "x9.23";
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

        while (inoff < in.length - 1)
        {
            if (random == null)
            {
                in[inoff] = 0;
            }
            else
            {
                in[inoff] = (byte)random.nextint();
            }
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
