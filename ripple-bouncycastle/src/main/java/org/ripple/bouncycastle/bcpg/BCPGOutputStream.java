package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;
import java.io.outputstream;

/**
 * basic output stream.
 */
public class bcpgoutputstream
    extends outputstream
    implements packettags, compressionalgorithmtags
{
    outputstream    out;
    private byte[]  partialbuffer;
    private int     partialbufferlength;
    private int     partialpower;
    private int     partialoffset;
    
    private static final int    buf_size_power = 16; // 2^16 size buffer on long files
    
    public bcpgoutputstream(
        outputstream    out)
    {
        this.out = out;
    }
    
    /**
     * create a stream representing an old style partial object.
     * 
     * @param tag the packet tag for the object.
     */
    public bcpgoutputstream(
        outputstream    out,
        int             tag)
        throws ioexception
    {
        this.out = out;
        this.writeheader(tag, true, true, 0);
    }
    
    /**
     * create a stream representing a general packet.
     * 
     * @param out
     * @param tag
     * @param length
     * @param oldformat
     * @throws ioexception
     */
    public bcpgoutputstream(
        outputstream    out,
        int             tag,
        long            length,
        boolean         oldformat)
        throws ioexception
    {
        this.out = out;
        
        if (length > 0xffffffffl)
        {
            this.writeheader(tag, false, true, 0);
            this.partialbufferlength = 1 << buf_size_power;
            this.partialbuffer = new byte[partialbufferlength];
            this.partialpower = buf_size_power;
            this.partialoffset = 0;
        }
        else
        {
            this.writeheader(tag, oldformat, false, length);
        }
    }
    
    /**
     * 
     * @param tag
     * @param length
     * @throws ioexception
     */
    public bcpgoutputstream(
        outputstream    out,
        int             tag,
        long            length)
        throws ioexception
    {
        this.out = out;
        
        this.writeheader(tag, false, false, length);
    }
    
    /**
     * create a new style partial input stream buffered into chunks.
     * 
     * @param out output stream to write to.
     * @param tag packet tag.
     * @param buffer size of chunks making up the packet.
     * @throws ioexception
     */
    public bcpgoutputstream(
        outputstream    out,
        int             tag,
        byte[]          buffer)
        throws ioexception
    {
        this.out = out;
        this.writeheader(tag, false, true, 0);
        
        this.partialbuffer = buffer;
        
        int    length = partialbuffer.length;
        
        for (partialpower = 0; length != 1; partialpower++)
        {
            length >>>= 1;
        }
        
        if (partialpower > 30)
        {
            throw new ioexception("buffer cannot be greater than 2^30 in length.");
        }
        
        this.partialbufferlength = 1 << partialpower;
        this.partialoffset = 0;
    }
    
    private void writenewpacketlength(
        long            bodylen) 
        throws ioexception
    {
        if (bodylen < 192)
        {
            out.write((byte)bodylen);
        }
        else if (bodylen <= 8383)
        {
            bodylen -= 192;
                    
            out.write((byte)(((bodylen >> 8) & 0xff) + 192));
            out.write((byte)bodylen);
        }
        else
        {
            out.write(0xff);
            out.write((byte)(bodylen >> 24));
            out.write((byte)(bodylen >> 16));
            out.write((byte)(bodylen >> 8));
            out.write((byte)bodylen);
        }
    }
    
    private void writeheader(
        int        tag,
        boolean    oldpackets,
        boolean    partial,
        long       bodylen) 
        throws ioexception
    {
        int    hdr = 0x80;
        
        if (partialbuffer != null)
        {
            partialflush(true);
            partialbuffer = null;
        }
        
        if (oldpackets)
        {
            hdr |= tag << 2;
            
            if (partial)
            {
                this.write(hdr | 0x03);
            }
            else
            {
                if (bodylen <= 0xff)
                {
                    this.write(hdr);
                    this.write((byte)bodylen);
                }
                else if (bodylen <= 0xffff)
                {
                    this.write(hdr | 0x01);
                    this.write((byte)(bodylen >> 8));
                    this.write((byte)(bodylen));
                }
                else
                {
                    this.write(hdr | 0x02);
                    this.write((byte)(bodylen >> 24));
                    this.write((byte)(bodylen >> 16));
                    this.write((byte)(bodylen >> 8));
                    this.write((byte)bodylen);
                }
            }
        }
        else
        {
            hdr |= 0x40 | tag;
            this.write(hdr);
            
            if (partial)
            {
                partialoffset = 0;
            }
            else
            {
                this.writenewpacketlength(bodylen);
            }
        }
    }
    
    private void partialflush(
        boolean islast) 
        throws ioexception
    {
        if (islast)
        {
            writenewpacketlength(partialoffset);
            out.write(partialbuffer, 0, partialoffset);
        }
        else
        {
            out.write(0xe0 | partialpower);
            out.write(partialbuffer, 0, partialbufferlength);
        }
        
        partialoffset = 0;
    }
    
    private void writepartial(
        byte    b) 
        throws ioexception
    {
        if (partialoffset == partialbufferlength)
        {
            partialflush(false);
        }
        
        partialbuffer[partialoffset++] = b;
    }
    
    private void writepartial(
        byte[]  buf,
        int     off,
        int     len) 
        throws ioexception
    {
        if (partialoffset == partialbufferlength)
        {
            partialflush(false);
        }
        
        if (len <= (partialbufferlength - partialoffset))
        {
            system.arraycopy(buf, off, partialbuffer, partialoffset, len);
            partialoffset += len;
        }
        else
        {
            system.arraycopy(buf, off, partialbuffer, partialoffset, partialbufferlength - partialoffset);
            off += partialbufferlength - partialoffset;
            len -= partialbufferlength - partialoffset;
            partialflush(false);
            
            while (len > partialbufferlength)
            {
                system.arraycopy(buf, off, partialbuffer, 0, partialbufferlength);
                off += partialbufferlength;
                len -= partialbufferlength;
                partialflush(false);
            }

            system.arraycopy(buf, off, partialbuffer, 0, len);
            partialoffset += len;
        }
    }
    
    public void write(
        int    b)
        throws ioexception
    {
        if (partialbuffer != null)
        {
            writepartial((byte)b);
        }
        else
        {
            out.write(b);
        }
    }
    
    public void write(
        byte[]    bytes,
        int       off,
        int       len)
        throws ioexception
    {
        if (partialbuffer != null)
        {
            writepartial(bytes, off, len);
        }
        else
        {
            out.write(bytes, off, len);
        }
    }
    
    public void writepacket(
        containedpacket    p)
        throws ioexception
    {
        p.encode(this);
    }
    
    void writepacket(
        int        tag,
        byte[]     body,
        boolean    oldformat)
        throws ioexception
    {
        this.writeheader(tag, oldformat, false, body.length);
        this.write(body);
    }
    
    public void writeobject(
        bcpgobject    o)
        throws ioexception
    {
        o.encode(this);
    }
    
    /**
     * flush the underlying stream.
     */
    public void flush()
        throws ioexception
    {
        out.flush();
    }
    
    /**
     * finish writing out the current packet without closing the underlying stream.
     */
    public void finish() 
        throws ioexception
    {
        if (partialbuffer != null)
        {
            partialflush(true);
            partialbuffer = null;
        }
    }
    
    public void close()
        throws ioexception
    {
        this.finish();
        out.flush();
        out.close();
    }
}
