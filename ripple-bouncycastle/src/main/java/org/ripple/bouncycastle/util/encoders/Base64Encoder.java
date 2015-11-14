package org.ripple.bouncycastle.util.encoders;

import java.io.ioexception;
import java.io.outputstream;

public class base64encoder
    implements encoder
{
    protected final byte[] encodingtable =
        {
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v',
            (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
            (byte)'7', (byte)'8', (byte)'9',
            (byte)'+', (byte)'/'
        };

    protected byte    padding = (byte)'=';
    
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
    }
    
    public base64encoder()
    {
        initialisedecodingtable();
    }
    
    /**
     * encode the input data producing a base 64 output stream.
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
        int modulus = length % 3;
        int datalength = (length - modulus);
        int a1, a2, a3;
        
        for (int i = off; i < off + datalength; i += 3)
        {
            a1 = data[i] & 0xff;
            a2 = data[i + 1] & 0xff;
            a3 = data[i + 2] & 0xff;

            out.write(encodingtable[(a1 >>> 2) & 0x3f]);
            out.write(encodingtable[((a1 << 4) | (a2 >>> 4)) & 0x3f]);
            out.write(encodingtable[((a2 << 2) | (a3 >>> 6)) & 0x3f]);
            out.write(encodingtable[a3 & 0x3f]);
        }

        /*
         * process the tail end.
         */
        int    b1, b2, b3;
        int    d1, d2;

        switch (modulus)
        {
        case 0:        /* nothing left to do */
            break;
        case 1:
            d1 = data[off + datalength] & 0xff;
            b1 = (d1 >>> 2) & 0x3f;
            b2 = (d1 << 4) & 0x3f;

            out.write(encodingtable[b1]);
            out.write(encodingtable[b2]);
            out.write(padding);
            out.write(padding);
            break;
        case 2:
            d1 = data[off + datalength] & 0xff;
            d2 = data[off + datalength + 1] & 0xff;

            b1 = (d1 >>> 2) & 0x3f;
            b2 = ((d1 << 4) | (d2 >>> 4)) & 0x3f;
            b3 = (d2 << 2) & 0x3f;

            out.write(encodingtable[b1]);
            out.write(encodingtable[b2]);
            out.write(encodingtable[b3]);
            out.write(padding);
            break;
        }

        return (datalength / 3) * 4 + ((modulus == 0) ? 0 : 4);
    }

    private boolean ignore(
        char    c)
    {
        return (c == '\n' || c =='\r' || c == '\t' || c == ' ');
    }
    
    /**
     * decode the base 64 encoded byte data writing it to the given output stream,
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
        byte    b1, b2, b3, b4;
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
        
        int  i = off;
        int  finish = end - 4;
        
        i = nexti(data, i, finish);

        while (i < finish)
        {
            b1 = decodingtable[data[i++]];
            
            i = nexti(data, i, finish);
            
            b2 = decodingtable[data[i++]];
            
            i = nexti(data, i, finish);
            
            b3 = decodingtable[data[i++]];
            
            i = nexti(data, i, finish);
            
            b4 = decodingtable[data[i++]];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new ioexception("invalid characters encountered in base64 data");
            }
            
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
            
            outlen += 3;
            
            i = nexti(data, i, finish);
        }

        outlen += decodelastblock(out, (char)data[end - 4], (char)data[end - 3], (char)data[end - 2], (char)data[end - 1]);
        
        return outlen;
    }

    private int nexti(byte[] data, int i, int finish)
    {
        while ((i < finish) && ignore((char)data[i]))
        {
            i++;
        }
        return i;
    }
    
    /**
     * decode the base 64 encoded string data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        string          data,
        outputstream    out)
        throws ioexception
    {
        byte    b1, b2, b3, b4;
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
        
        int  i = 0;
        int  finish = end - 4;
        
        i = nexti(data, i, finish);
        
        while (i < finish)
        {
            b1 = decodingtable[data.charat(i++)];
            
            i = nexti(data, i, finish);
            
            b2 = decodingtable[data.charat(i++)];
            
            i = nexti(data, i, finish);
            
            b3 = decodingtable[data.charat(i++)];
            
            i = nexti(data, i, finish);
            
            b4 = decodingtable[data.charat(i++)];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new ioexception("invalid characters encountered in base64 data");
            }
               
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
            
            length += 3;
            
            i = nexti(data, i, finish);
        }

        length += decodelastblock(out, data.charat(end - 4), data.charat(end - 3), data.charat(end - 2), data.charat(end - 1));

        return length;
    }

    private int decodelastblock(outputstream out, char c1, char c2, char c3, char c4) 
        throws ioexception
    {
        byte    b1, b2, b3, b4;
        
        if (c3 == padding)
        {
            b1 = decodingtable[c1];
            b2 = decodingtable[c2];

            if ((b1 | b2) < 0)
            {
                throw new ioexception("invalid characters encountered at end of base64 data");
            }

            out.write((b1 << 2) | (b2 >> 4));
            
            return 1;
        }
        else if (c4 == padding)
        {
            b1 = decodingtable[c1];
            b2 = decodingtable[c2];
            b3 = decodingtable[c3];

            if ((b1 | b2 | b3) < 0)
            {
                throw new ioexception("invalid characters encountered at end of base64 data");
            }
            
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            
            return 2;
        }
        else
        {
            b1 = decodingtable[c1];
            b2 = decodingtable[c2];
            b3 = decodingtable[c3];
            b4 = decodingtable[c4];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new ioexception("invalid characters encountered at end of base64 data");
            }
            
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
            
            return 3;
        } 
    }

    private int nexti(string data, int i, int finish)
    {
        while ((i < finish) && ignore(data.charat(i)))
        {
            i++;
        }
        return i;
    }
}
