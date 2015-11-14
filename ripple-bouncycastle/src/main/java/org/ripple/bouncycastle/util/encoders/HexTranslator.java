package org.ripple.bouncycastle.util.encoders;

/**
 * converters for going from hex to binary and back. note: this class assumes ascii processing.
 */
public class hextranslator
    implements translator
{
    private static final byte[]   hextable = 
        { 
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
            (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
        };

    /**
     * size of the output block on encoding produced by getdecodedblocksize()
     * bytes.
     */
    public int getencodedblocksize()
    {
        return 2;
    }

    public int encode(
        byte[]  in,
        int     inoff,
        int     length,
        byte[]  out,
        int     outoff)
    {
        for (int i = 0, j = 0; i < length; i++, j += 2)
        {
            out[outoff + j] = hextable[(in[inoff] >> 4) & 0x0f];
            out[outoff + j + 1] = hextable[in[inoff] & 0x0f];

            inoff++;
        }

        return length * 2;
    }

    /**
     * size of the output block on decoding produced by getencodedblocksize()
     * bytes.
     */
    public int getdecodedblocksize()
    {
        return 1;
    }

    public int decode(
        byte[]  in,
        int     inoff,
        int     length,
        byte[]  out,
        int     outoff)
    {
        int halflength = length / 2;
        byte left, right;
        for (int i = 0; i < halflength; i++)
        {
            left  = in[inoff + i * 2];
            right = in[inoff + i * 2 + 1];
            
            if (left < (byte)'a')
            {
                out[outoff] = (byte)((left - '0') << 4);
            }
            else
            {
                out[outoff] = (byte)((left - 'a' + 10) << 4);
            }
            if (right < (byte)'a')
            {
                out[outoff] += (byte)(right - '0');
            }
            else
            {
                out[outoff] += (byte)(right - 'a' + 10);
            }

            outoff++;
        }

        return halflength;
    }
}
