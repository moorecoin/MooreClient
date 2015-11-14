package org.ripple.bouncycastle.bcpg;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.util.io.streams;

/**
 * reader for pgp objects
 */
public class bcpginputstream
    extends inputstream implements packettags
{
    inputstream    in;
    boolean        next = false;
    int            nextb;
    
    public bcpginputstream(
        inputstream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws ioexception
    {
        return in.available();
    }
    
    public int read()
        throws ioexception
    {
        if (next)
        {
            next = false;

            return nextb;
        }
        else
        {
            return in.read();
        }
    }

    public int read(
        byte[] buf,
        int off,
        int len)
        throws ioexception
    {
        if (len == 0)
        {
            return 0;
        }

        if (!next)
        {
            return in.read(buf, off, len);
        }

        // we have next byte waiting, so return it

        if (nextb < 0)
        {
            return -1; // eof
        }

        buf[off] = (byte)nextb;  // may throw nullpointerexception...
        next = false;            // ...so only set this afterwards

        return 1;
    }

    public void readfully(
        byte[]    buf,
        int       off,
        int       len)
        throws ioexception
    {
        if (streams.readfully(this, buf, off, len) < len)
        {
            throw new eofexception();
        }
    }

    public byte[] readall()
        throws ioexception
    {
        return streams.readall(this);
    }

    public void readfully(
        byte[]    buf)
        throws ioexception
    {
        readfully(buf, 0, buf.length);
    }

    /**
     * returns the next packet tag in the stream.
     * 
     * @return the tag number.
     * 
     * @throws ioexception
     */
    public int nextpackettag()
        throws ioexception
    {
        if (!next)
        {
            try
            {
                nextb = in.read();
            }
            catch (eofexception e)
            {
                nextb = -1;
            }
        } 
        
        next = true;

        if (nextb >= 0)
        {
            if ((nextb & 0x40) != 0)    // new
            {
                return (nextb & 0x3f);
            }
            else    // old
            {
                return ((nextb & 0x3f) >> 2);
            }
        }
        
        return nextb;
    }

    public packet readpacket()
        throws ioexception
    {
        int    hdr = this.read();
        
        if (hdr < 0)
        {
            return null;
        }
        
        if ((hdr & 0x80) == 0)
        {
            throw new ioexception("invalid header encountered");
        }

        boolean    newpacket = (hdr & 0x40) != 0;
        int        tag = 0;
        int        bodylen = 0;
        boolean    partial = false;
        
        if (newpacket)
        {
            tag = hdr & 0x3f;
            
            int    l = this.read();

            if (l < 192)
            {
                bodylen = l;
            }
            else if (l <= 223)
            {
                int b = in.read();

                bodylen = ((l - 192) << 8) + (b) + 192;
            }
            else if (l == 255)
            {
                bodylen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
            }
            else
            {
                partial = true;
                bodylen = 1 << (l & 0x1f);
            }
        }
        else
        {
            int lengthtype = hdr & 0x3;
            
            tag = (hdr & 0x3f) >> 2;

            switch (lengthtype)
            {
            case 0:
                bodylen = this.read();
                break;
            case 1:
                bodylen = (this.read() << 8) | this.read();
                break;
            case 2:
                bodylen = (this.read() << 24) | (this.read() << 16) | (this.read() << 8) | this.read();
                break;
            case 3:
                partial = true;
                break;
            default:
                throw new ioexception("unknown length type encountered");
            }
        }

        bcpginputstream    objstream;
        
        if (bodylen == 0 && partial)
        {
            objstream = this;
        }
        else
        {
            objstream = new bcpginputstream(new partialinputstream(this, partial, bodylen));
        }

        switch (tag)
        {
        case reserved:
            return new inputstreampacket(objstream);
        case public_key_enc_session:
            return new publickeyencsessionpacket(objstream);
        case signature:
            return new signaturepacket(objstream);
        case symmetric_key_enc_session:
            return new symmetrickeyencsessionpacket(objstream);
        case one_pass_signature:
            return new onepasssignaturepacket(objstream);
        case secret_key:
            return new secretkeypacket(objstream);
        case public_key:
            return new publickeypacket(objstream);
        case secret_subkey:
            return new secretsubkeypacket(objstream);
        case compressed_data:
            return new compresseddatapacket(objstream);
        case symmetric_key_enc:
            return new symmetricencdatapacket(objstream);
        case marker:
            return new markerpacket(objstream);
        case literal_data:
            return new literaldatapacket(objstream);
        case trust:
            return new trustpacket(objstream);
        case user_id:
            return new useridpacket(objstream);
        case user_attribute:
            return new userattributepacket(objstream);
        case public_subkey:
            return new publicsubkeypacket(objstream);
        case sym_enc_integrity_pro:
            return new symmetricencintegritypacket(objstream);
        case mod_detection_code:
            return new moddetectioncodepacket(objstream);
        case experimental_1:
        case experimental_2:
        case experimental_3:
        case experimental_4:
            return new experimentalpacket(tag, objstream);
        default:
            throw new ioexception("unknown packet type encountered: " + tag);
        }
    }
    
    public void close()
        throws ioexception
    {
        in.close();
    }
    
    /**
     * a stream that overlays our input stream, allowing the user to only read a segment of it.
     *
     * nb: datalength will be negative if the segment length is in the upper range above 2**31.
     */
    private static class partialinputstream
        extends inputstream
    {
        private bcpginputstream     in;
        private boolean             partial;
        private int                 datalength;

        partialinputstream(
            bcpginputstream  in,
            boolean          partial,
            int              datalength)
        {
            this.in = in;
            this.partial = partial;
            this.datalength = datalength;
        }

        public int available()
            throws ioexception
        {
            int avail = in.available();

            if (avail <= datalength || datalength < 0)
            {
                return avail;
            }
            else
            {
                if (partial && datalength == 0)
                {
                    return 1;
                }
                return datalength;
            }
        }

        private int loaddatalength()
            throws ioexception
        {
            int            l = in.read();
            
            if (l < 0)
            {
                return -1;
            }
            
            partial = false;
            if (l < 192)
            {
                datalength = l;
            }
            else if (l <= 223)
            {
                datalength = ((l - 192) << 8) + (in.read()) + 192;
            }
            else if (l == 255)
            {
                datalength = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
            }
            else
            {
                partial = true;
                datalength = 1 << (l & 0x1f);
            }
            
            return datalength;
        }
        
        public int read(byte[] buf, int offset, int len)
            throws ioexception
        {
            do
            {
                if (datalength != 0)
                {
                    int readlen = (datalength > len || datalength < 0) ? len : datalength;
                    readlen = in.read(buf, offset, readlen);
                    if (readlen < 0)
                    {
                        throw new eofexception("premature end of stream in partialinputstream");
                    }
                    datalength -= readlen;
                    return readlen;
                }
            }
            while (partial && loaddatalength() >= 0);

            return -1;
        }
        
        public int read()
            throws ioexception
        {
            do
            {
                if (datalength != 0)
                {
                    int ch = in.read();
                    if (ch < 0)
                    {
                        throw new eofexception("premature end of stream in partialinputstream");
                    }
                    datalength--;
                    return ch;
                }
            }
            while (partial && loaddatalength() >= 0);

            return -1;
        }
    }
}
