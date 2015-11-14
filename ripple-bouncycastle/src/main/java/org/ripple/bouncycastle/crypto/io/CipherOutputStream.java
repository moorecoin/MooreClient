package org.ripple.bouncycastle.crypto.io;

import java.io.filteroutputstream;
import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.streamcipher;

public class cipheroutputstream
    extends filteroutputstream
{
    private bufferedblockcipher bufferedblockcipher;
    private streamcipher streamcipher;

    private byte[] onebyte = new byte[1];
    private byte[] buf;

    /**
     * constructs a cipheroutputstream from an outputstream and a
     * bufferedblockcipher.
     */
    public cipheroutputstream(
        outputstream os,
        bufferedblockcipher cipher)
    {
        super(os);
        this.bufferedblockcipher = cipher;
        this.buf = new byte[cipher.getblocksize()];
    }

    /**
     * constructs a cipheroutputstream from an outputstream and a
     * bufferedblockcipher.
     */
    public cipheroutputstream(
        outputstream os,
        streamcipher cipher)
    {
        super(os);
        this.streamcipher = cipher;
    }

    /**
     * writes the specified byte to this output stream.
     *
     * @param b the <code>byte</code>.
     * @exception java.io.ioexception if an i/o error occurs.
     */
    public void write(
        int b)
        throws ioexception
    {
        onebyte[0] = (byte)b;

        if (bufferedblockcipher != null)
        {
            int len = bufferedblockcipher.processbytes(onebyte, 0, 1, buf, 0);

            if (len != 0)
            {
                out.write(buf, 0, len);
            }
        }
        else
        {
            out.write(streamcipher.returnbyte((byte)b));
        }
    }

    /**
     * writes <code>b.length</code> bytes from the specified byte array
     * to this output stream.
     * <p>
     * the <code>write</code> method of
     * <code>cipheroutputstream</code> calls the <code>write</code>
     * method of three arguments with the three arguments
     * <code>b</code>, <code>0</code>, and <code>b.length</code>.
     *
     * @param b the data.
     * @exception java.io.ioexception if an i/o error occurs.
     * @see #write(byte[], int, int)
     */
    public void write(
        byte[] b)
        throws ioexception
    {
        write(b, 0, b.length);
    }

    /**
     * writes <code>len</code> bytes from the specified byte array
     * starting at offset <code>off</code> to this output stream.
     *
     * @param b the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     * @exception java.io.ioexception if an i/o error occurs.
     */
    public void write(
        byte[] b,
        int off,
        int len)
        throws ioexception
    {
        if (bufferedblockcipher != null)
        {
            byte[] buf = new byte[bufferedblockcipher.getoutputsize(len)];

            int outlen = bufferedblockcipher.processbytes(b, off, len, buf, 0);

            if (outlen != 0)
            {
                out.write(buf, 0, outlen);
            }
        }
        else
        {
            byte[] buf = new byte[len];

            streamcipher.processbytes(b, off, len, buf, 0);

            out.write(buf, 0, len);
        }
    }

    /**
     * flushes this output stream by forcing any buffered output bytes
     * that have already been processed by the encapsulated cipher object
     * to be written out.
     *
     * <p>
     * any bytes buffered by the encapsulated cipher
     * and waiting to be processed by it will not be written out. for example,
     * if the encapsulated cipher is a block cipher, and the total number of
     * bytes written using one of the <code>write</code> methods is less than
     * the cipher's block size, no bytes will be written out.
     *
     * @exception java.io.ioexception if an i/o error occurs.
     */
    public void flush()
        throws ioexception
    {
        super.flush();
    }

    /**
     * closes this output stream and releases any system resources
     * associated with this stream.
     * <p>
     * this method invokes the <code>dofinal</code> method of the encapsulated
     * cipher object, which causes any bytes buffered by the encapsulated
     * cipher to be processed. the result is written out by calling the
     * <code>flush</code> method of this output stream.
     * <p>
     * this method resets the encapsulated cipher object to its initial state
     * and calls the <code>close</code> method of the underlying output
     * stream.
     *
     * @exception java.io.ioexception if an i/o error occurs.
     */
    public void close()
        throws ioexception
    {
        try
        {
            if (bufferedblockcipher != null)
            {
                byte[] buf = new byte[bufferedblockcipher.getoutputsize(0)];

                int outlen = bufferedblockcipher.dofinal(buf, 0);

                if (outlen != 0)
                {
                    out.write(buf, 0, outlen);
                }
            }
        }
        catch (exception e)
        {
            throw new ioexception("error closing stream: " + e.tostring());
        }

        flush();

        super.close();
    }
}
