package org.ripple.bouncycastle.openpgp;

import org.ripple.bouncycastle.apache.bzip2.cbzip2outputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.compressionalgorithmtags;
import org.ripple.bouncycastle.bcpg.packettags;

import java.io.ioexception;
import java.io.outputstream;
import java.util.zip.deflater;
import java.util.zip.deflateroutputstream;

/**
 *class for producing compressed data packets.
 */
public class pgpcompresseddatagenerator 
    implements compressionalgorithmtags, streamgenerator
{
    private int                     algorithm;
    private int                     compression;

    private outputstream            dout;
    private bcpgoutputstream        pkout;
    
    public pgpcompresseddatagenerator(
        int                    algorithm)
    {
        this(algorithm, deflater.default_compression);
    }
                    
    public pgpcompresseddatagenerator(
        int                    algorithm,
        int                    compression)
    {
        switch (algorithm)
        {
            case compressionalgorithmtags.uncompressed:
            case compressionalgorithmtags.zip:
            case compressionalgorithmtags.zlib:
            case compressionalgorithmtags.bzip2:
                break;
            default:
                throw new illegalargumentexception("unknown compression algorithm");
        }

        if (compression != deflater.default_compression)
        {
            if ((compression < deflater.no_compression) || (compression > deflater.best_compression))
            {
                throw new illegalargumentexception("unknown compression level: " + compression);
            }
        }

        this.algorithm = algorithm;
        this.compression = compression;
    }

    /**
     * return an outputstream which will save the data being written to 
     * the compressed object.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * 
     * @param out underlying outputstream to be used.
     * @return outputstream
     * @throws ioexception, illegalstateexception
     */        
    public outputstream open(
        outputstream    out)
        throws ioexception
    {
        if (dout != null)
        {
            throw new illegalstateexception("generator already in open state");
        }

        this.pkout = new bcpgoutputstream(out, packettags.compressed_data);

        doopen();

        return new wrappedgeneratorstream(dout, this);
    }
    
    /**
     * return an outputstream which will compress the data as it is written
     * to it. the stream will be written out in chunks according to the size of the
     * passed in buffer.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * <p>
     * <b>note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * </p>
     * <p>
     * <b>note</b>: using this may break compatibility with rfc 1991 compliant tools. only recent openpgp
     * implementations are capable of accepting these streams.
     * </p>
     * 
     * @param out underlying outputstream to be used.
     * @param buffer the buffer to use.
     * @return outputstream
     * @throws ioexception
     * @throws pgpexception
     */
    public outputstream open(
        outputstream    out,
        byte[]          buffer)
        throws ioexception, pgpexception
    {
        if (dout != null)
        {
            throw new illegalstateexception("generator already in open state");
        }

        this.pkout = new bcpgoutputstream(out, packettags.compressed_data, buffer);

        doopen();

        return new wrappedgeneratorstream(dout, this);
    }

    private void doopen() throws ioexception
    {
        pkout.write(algorithm);

        switch (algorithm)
        {
            case compressionalgorithmtags.uncompressed:
                dout = pkout;
                break;
            case compressionalgorithmtags.zip:
                dout = new safedeflateroutputstream(pkout, compression, true);
                break;
            case compressionalgorithmtags.zlib:
                dout = new safedeflateroutputstream(pkout, compression, false);
                break;
            case compressionalgorithmtags.bzip2:
                dout = new safecbzip2outputstream(pkout);
                break;
            default:
                // constructor should guard against this possibility
                throw new illegalstateexception();
        }
    }

    /**
     * close the compressed object - this is equivalent to calling close on the stream
     * returned by the open() method.
     * 
     * @throws ioexception
     */
    public void close()
        throws ioexception
    {
        if (dout != null)
        {
            if (dout != pkout)
            {
                dout.close();
                dout.flush();
            }

            dout = null;

            pkout.finish();
            pkout.flush();
            pkout = null;
        }
    }

    private static class safecbzip2outputstream extends cbzip2outputstream
    {
        public safecbzip2outputstream(outputstream output) throws ioexception
        {
            super(output);
        }

        public void close() throws ioexception
        {
            finish();
        }
    }

    private class safedeflateroutputstream extends deflateroutputstream
    {
        public safedeflateroutputstream(outputstream output, int compression, boolean nowrap)
        {
            super(output, new deflater(compression, nowrap));
        }

        public void close() throws ioexception
        {
            finish();
            def.end();
        }
    }
}
