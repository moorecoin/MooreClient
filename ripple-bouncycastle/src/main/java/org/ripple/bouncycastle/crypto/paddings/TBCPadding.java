package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a padder that adds trailing-bit-compliment padding to a block.
 * <p>
 * this padding pads the block out with the compliment of the last bit
 * of the plain text.
 * </p>
 */
public class tbcpadding
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
        return "tbc";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     * <p>
     * note: this assumes that the last block of plain text is always 
     * passed to it inside in. i.e. if inoff is zero, indicating the
     * entire block is to be overwritten with padding the value of in
     * should be the same as the last block of plain text.
     * </p>
     */
    public int addpadding(
        byte[]  in,
        int     inoff)
    {
        int     count = in.length - inoff;
        byte    code;
        
        if (inoff > 0)
        {
            code = (byte)((in[inoff - 1] & 0x01) == 0 ? 0xff : 0x00);
        }
        else
        {
            code = (byte)((in[in.length - 1] & 0x01) == 0 ? 0xff : 0x00);
        }
            
        while (inoff < in.length)
        {
            in[inoff] = code;
            inoff++;
        }

        return count;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padcount(byte[] in)
        throws invalidciphertextexception
    {
        byte code = in[in.length - 1];

        int index = in.length - 1;
        while (index > 0 && in[index - 1] == code)
        {
            index--;
        }

        return in.length - index;
    }
}
