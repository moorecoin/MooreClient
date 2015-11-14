package org.moorecoinlab.btc;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;

/**
 * an unsynchronized implementation of bytearrayoutputstream that will return the backing byte array if its length == size().
 * this avoids unneeded array copy where the bos is simply being used to extract a byte array of known length from a
 * 'serialized to stream' method.
 * <p/>
 * unless the final length can be accurately predicted the only performance this will yield is due to unsynchronized
 * methods.
 *
 * @author git
 */
public class unsafebytearrayoutputstream extends bytearrayoutputstream {

    public unsafebytearrayoutputstream() {
        super(32);
    }

    public unsafebytearrayoutputstream(int size) {
        super(size);
    }

    /**
     * writes the specified byte to this byte array output stream.
     *
     * @param b the byte to be written.
     */
    public void write(int b) {
        int newcount = count + 1;
        if (newcount > buf.length) {
            buf = bitutil.copyof(buf, math.max(buf.length << 1, newcount));
        }
        buf[count] = (byte) b;
        count = newcount;
    }

    /**
     * writes <code>len</code> bytes from the specified byte array
     * starting at offset <code>off</code> to this byte array output stream.
     *
     * @param b   the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     */
    public void write(byte b[], int off, int len) {
        if ((off < 0) || (off > b.length) || (len < 0) ||
                ((off + len) > b.length) || ((off + len) < 0)) {
            throw new indexoutofboundsexception();
        } else if (len == 0) {
            return;
        }
        int newcount = count + len;
        if (newcount > buf.length) {
            buf = bitutil.copyof(buf, math.max(buf.length << 1, newcount));
        }
        system.arraycopy(b, off, buf, count, len);
        count = newcount;
    }

    /**
     * writes the complete contents of this byte array output stream to
     * the specified output stream argument, as if by calling the output
     * stream's write method using <code>out.write(buf, 0, count)</code>.
     *
     * @param out the output stream to which to write the data.
     * @throws java.io.ioexception if an i/o error occurs.
     */
    public void writeto(outputstream out) throws ioexception {
        out.write(buf, 0, count);
    }

    /**
     * resets the <code>count</code> field of this byte array output
     * stream to zero, so that all currently accumulated output in the
     * output stream is discarded. the output stream can be used again,
     * reusing the already allocated buffer space.
     *
     * @see java.io.bytearrayinputstream#count
     */
    public void reset() {
        count = 0;
    }

    /**
     * creates a newly allocated byte array. its size is the current
     * size of this output stream and the valid contents of the buffer
     * have been copied into it.
     *
     * @return the current contents of this output stream, as a byte array.
     * @see java.io.bytearrayoutputstream#size()
     */
    public byte tobytearray()[] {
        return count == buf.length ? buf : bitutil.copyof(buf, count);
    }

    /**
     * returns the current size of the buffer.
     *
     * @return the value of the <code>count</code> field, which is the number
     *         of valid bytes in this output stream.
     * @see java.io.bytearrayoutputstream#count
     */
    public int size() {
        return count;
    }

}
