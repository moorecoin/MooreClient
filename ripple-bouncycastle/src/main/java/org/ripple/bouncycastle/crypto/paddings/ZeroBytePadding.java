package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a padder that adds null byte padding to a block.
 */
public class zerobytepadding
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
        return "zerobyte";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    public int addpadding(
        byte[]  in,
        int     inoff)
    {
        int added = (in.length - inoff);

        while (inoff < in.length)
        {
            in[inoff] = (byte) 0;
            inoff++;
        }

        return added;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padcount(byte[] in)
        throws invalidciphertextexception
    {
        int count = in.length;

        while (count > 0)
        {
            if (in[count - 1] != 0)
            {
                break;
            }

            count--;
        }

        return in.length - count;
    }
}
