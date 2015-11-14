package org.ripple.bouncycastle.util.encoders;


/**
 * a buffering class to allow translation from one format to another to
 * be done in discrete chunks.
 */
public class buffereddecoder
{
    protected byte[]        buf;
    protected int           bufoff;

    protected translator    translator;

    /**
     * @param translator the translator to use.
     * @param bufsize amount of input to buffer for each chunk.
     */
    public buffereddecoder(
        translator  translator,
        int         bufsize)
    {
        this.translator = translator;

        if ((bufsize % translator.getencodedblocksize()) != 0)
        {
            throw new illegalargumentexception("buffer size not multiple of input block size");
        }

        buf = new byte[bufsize];
        bufoff = 0;
    }

    public int processbyte(
        byte        in,
        byte[]      out,
        int         outoff)
    {
        int         resultlen = 0;

        buf[bufoff++] = in;

        if (bufoff == buf.length)
        {
            resultlen = translator.decode(buf, 0, buf.length, out, outoff);
            bufoff = 0;
        }

        return resultlen;
    }

    public int processbytes(
        byte[]      in,
        int         inoff,
        int         len,
        byte[]      out,
        int         outoff)
    {
        if (len < 0)
        {
            throw new illegalargumentexception("can't have a negative input length!");
        }

        int resultlen = 0;
        int gaplen = buf.length - bufoff;

        if (len > gaplen)
        {
            system.arraycopy(in, inoff, buf, bufoff, gaplen);

            resultlen += translator.decode(buf, 0, buf.length, out, outoff);

            bufoff = 0;

            len -= gaplen;
            inoff += gaplen;
            outoff += resultlen;

            int chunksize = len - (len % buf.length);

            resultlen += translator.decode(in, inoff, chunksize, out, outoff);

            len -= chunksize;
            inoff += chunksize;
        }

        if (len != 0)
        {
            system.arraycopy(in, inoff, buf, bufoff, len);

            bufoff += len;
        }

        return resultlen;
    }
}
