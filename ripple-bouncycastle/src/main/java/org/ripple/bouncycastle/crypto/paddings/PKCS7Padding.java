package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a padder that adds pkcs7/pkcs5 padding to a block.
 */
public class pkcs7padding
    implements blockcipherpadding
{
    /**
     * initialise the padder.
     *
     * @param random - a securerandom if available.
     */
    public void init(securerandom random)
        throws illegalargumentexception
    {
        // nothing to do.
    }

    /**
     * return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public string getpaddingname()
    {
        return "pkcs7";
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

        while (inoff < in.length)
        {
            in[inoff] = code;
            inoff++;
        }

        return code;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padcount(byte[] in)
        throws invalidciphertextexception
    {
        int count = in[in.length - 1] & 0xff;

        if (count > in.length || count == 0)
        {
            throw new invalidciphertextexception("pad block corrupted");
        }
        
        for (int i = 1; i <= count; i++)
        {
            if (in[in.length - i] != count)
            {
                throw new invalidciphertextexception("pad block corrupted");
            }
        }

        return count;
    }
}
