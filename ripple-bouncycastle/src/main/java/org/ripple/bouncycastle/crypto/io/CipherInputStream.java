package org.ripple.bouncycastle.crypto.io;

import java.io.filterinputstream;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.streamcipher;

/**
 * a cipherinputstream is composed of an inputstream and a bufferedblockcipher so
 * that read() methods return data that are read in from the
 * underlying inputstream but have been additionally processed by the
 * cipher.  the cipher must be fully initialized before being used by
 * a cipherinputstream.
 * <p>
 * for example, if the cipher is initialized for decryption, the
 * cipherinputstream will attempt to read in data and decrypt them,
 * before returning the decrypted data.
 */
public class cipherinputstream
    extends filterinputstream
{
    private bufferedblockcipher bufferedblockcipher;
    private streamcipher streamcipher;

    private byte[] buf;
    private byte[] inbuf;

    private int bufoff;
    private int maxbuf;
    private boolean finalized;

    private static final int input_buf_size = 2048;

    /**
     * constructs a cipherinputstream from an inputstream and a
     * bufferedblockcipher.
     */
    public cipherinputstream(
        inputstream is,
        bufferedblockcipher cipher)
    {
        super(is);

        this.bufferedblockcipher = cipher;

        buf = new byte[cipher.getoutputsize(input_buf_size)];
        inbuf = new byte[input_buf_size];
    }

    public cipherinputstream(
        inputstream is,
        streamcipher cipher)
    {
        super(is);

        this.streamcipher = cipher;

        buf = new byte[input_buf_size];
        inbuf = new byte[input_buf_size];
    }

    /**
     * grab the next chunk of input from the underlying input stream
     */
    private int nextchunk()
        throws ioexception
    {
        int available = super.available();

        // must always try to read 1 byte!
        // some buggy inputstreams return < 0!
        if (available <= 0)
        {
            available = 1;
        }

        if (available > inbuf.length)
        {
            available = super.read(inbuf, 0, inbuf.length);
        }
        else
        {
            available = super.read(inbuf, 0, available);
        }

        if (available < 0)
        {
            if (finalized)
            {
                return -1;
            }

            try
            {
                if (bufferedblockcipher != null)
                {
                    maxbuf = bufferedblockcipher.dofinal(buf, 0);
                }
                else
                {
                    maxbuf = 0; // a stream cipher
                }
            }
            catch (exception e)
            {
                throw new ioexception("error processing stream: " + e.tostring());
            }

            bufoff = 0;

            finalized = true;

            if (bufoff == maxbuf)
            {
                return -1;
            }
        }
        else
        {
            bufoff = 0;

            try
            {
                if (bufferedblockcipher != null)
                {
                    maxbuf = bufferedblockcipher.processbytes(inbuf, 0, available, buf, 0);
                }
                else
                {
                    streamcipher.processbytes(inbuf, 0, available, buf, 0);
                    maxbuf = available;
                }
            }
            catch (exception e)
            {
                throw new ioexception("error processing stream: " + e.tostring());
            }

            if (maxbuf == 0)    // not enough bytes read for first block...
            {
                return nextchunk();
            }
        }

        return maxbuf;
    }

    public int read()
        throws ioexception
    {
        if (bufoff == maxbuf)
        {
            if (nextchunk() < 0)
            {
                return -1;
            }
        }

        return buf[bufoff++] & 0xff;
    }

    public int read(
        byte[] b)
        throws ioexception
    {
        return read(b, 0, b.length);
    }

    public int read(
        byte[] b,
        int off,
        int len)
        throws ioexception
    {
        if (bufoff == maxbuf)
        {
            if (nextchunk() < 0)
            {
                return -1;
            }
        }

        int available = maxbuf - bufoff;

        if (len > available)
        {
            system.arraycopy(buf, bufoff, b, off, available);
            bufoff = maxbuf;

            return available;
        }
        else
        {
            system.arraycopy(buf, bufoff, b, off, len);
            bufoff += len;

            return len;
        }
    }

    public long skip(
        long n)
        throws ioexception
    {
        if (n <= 0)
        {
            return 0;
        }

        int available = maxbuf - bufoff;

        if (n > available)
        {
            bufoff = maxbuf;

            return available;
        }
        else
        {
            bufoff += (int)n;

            return (int)n;
        }
    }

    public int available()
        throws ioexception
    {
        return maxbuf - bufoff;
    }

    public void close()
        throws ioexception
    {
        super.close();
    }

    public boolean marksupported()
    {
        return false;
    }
}
