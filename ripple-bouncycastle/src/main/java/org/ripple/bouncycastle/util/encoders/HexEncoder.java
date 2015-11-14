package org.ripple.bouncycastle.util.encoders;

import java.io.ioexception;
import java.io.outputstream;

public class hexencoder
    implements encoder
{
    protected final byte[] encodingtable =
        {
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
            (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
        };
    
    /*
     * set up the decoding table.
     */
    protected final byte[] decodingtable = new byte[128];

    protected void initialisedecodingtable()
    {
        for (int i = 0; i < decodingtable.length; i++)
        {
            decodingtable[i] = (byte)0xff;
        }

        for (int i = 0; i < encodingtable.length; i++)
        {
            decodingtable[encodingtable[i]] = (byte)i;
        }
        
        decodingtable['a'] = decodingtable['a'];
        decodingtable['b'] = decodingtable['b'];
        decodingtable['c'] = decodingtable['c'];
        decodingtable['d'] = decodingtable['d'];
        decodingtable['e'] = decodingtable['e'];
        decodingtable['f'] = decodingtable['f'];
    }
    
    public hexencoder()
    {
        initialisedecodingtable();
    }
    
    /**
     * encode the input data producing a hex output stream.
     *
     * @return the number of bytes produced.
     */
    public int encode(
        byte[]                data,
        int                    off,
        int                    length,
        outputstream    out) 
        throws ioexception
    {        
        for (int i = off; i < (off + length); i++)
        {
            int    v = data[i] & 0xff;

            out.write(encodingtable[(v >>> 4)]);
            out.write(encodingtable[v & 0xf]);
        }

        return length * 2;
    }

    private static boolean ignore(
        char    c)
    {
        return c == '\n' || c =='\r' || c == '\t' || c == ' ';
    }

    /**
     * decode the hex encoded byte data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        byte[]          data,
        int             off,
        int             length,
        outputstream    out)
        throws ioexception
    {
        byte    b1, b2;
        int     outlen = 0;
        
        int     end = off + length;
        
        while (end > off)
        {
            if (!ignore((char)data[end - 1]))
            {
                break;
            }
            
            end--;
        }
        
        int i = off;
        while (i < end)
        {
            while (i < end && ignore((char)data[i]))
            {
                i++;
            }
            
            b1 = decodingtable[data[i++]];
            
            while (i < end && ignore((char)data[i]))
            {
                i++;
            }
            
            b2 = decodingtable[data[i++]];

            if ((b1 | b2) < 0)
            {
                throw new ioexception("invalid characters encountered in hex data");
            }

            out.write((b1 << 4) | b2);
            
            outlen++;
        }

        return outlen;
    }
    
    /**
     * decode the hex encoded string data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        string          data,
        outputstream    out)
        throws ioexception
    {
        byte    b1, b2;
        int     length = 0;
        
        int     end = data.length();
        
        while (end > 0)
        {
            if (!ignore(data.charat(end - 1)))
            {
                break;
            }
            
            end--;
        }
        
        int i = 0;
        while (i < end)
        {
            while (i < end && ignore(data.charat(i)))
            {
                i++;
            }
            
            b1 = decodingtable[data.charat(i++)];
            
            while (i < end && ignore(data.charat(i)))
            {
                i++;
            }
            
            b2 = decodingtable[data.charat(i++)];

            if ((b1 | b2) < 0)
            {
                throw new ioexception("invalid characters encountered in hex string");
            }

            out.write((b1 << 4) | b2);
            
            length++;
        }

        return length;
    }
}
