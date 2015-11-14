package org.ripple.bouncycastle.openpgp;

import java.io.file;
import java.io.ioexception;
import java.io.outputstream;
import java.util.date;

import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.util.strings;

/**
 * class for producing literal data packets.
 */
public class pgpliteraldatagenerator implements streamgenerator
{    
    public static final char    binary = pgpliteraldata.binary;
    public static final char    text = pgpliteraldata.text;
    public static final char    utf8 = pgpliteraldata.utf8;
    
    /**
     * the special name indicating a "for your eyes only" packet.
     */
    public static final string  console = pgpliteraldata.console;
    
    /**
     * the special time for a modification time of "now" or
     * the present time.
     */
    public static final date    now = pgpliteraldata.now;
    
    private bcpgoutputstream    pkout;
    private boolean             oldformat = false;
    
    public pgpliteraldatagenerator()
    {        
    }
    
    /**
     * generates literal data objects in the old format, this is
     * important if you need compatability with  pgp 2.6.x.
     * 
     * @param oldformat
     */
    public pgpliteraldatagenerator(
        boolean    oldformat)
    {
        this.oldformat = oldformat;
    }
    
    private void writeheader(
        outputstream    out,
        char            format,
        byte[]          encname,
        long            modificationtime) 
        throws ioexception
    {
        out.write(format);

        out.write((byte)encname.length);

        for (int i = 0; i != encname.length; i++)
        {
            out.write(encname[i]);
        }

        long    moddate = modificationtime / 1000;

        out.write((byte)(moddate >> 24));
        out.write((byte)(moddate >> 16));
        out.write((byte)(moddate >> 8));
        out.write((byte)(moddate));
    }
    
    /**
     * open a literal data packet, returning a stream to store the data inside
     * the packet.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * 
     * @param out the stream we want the packet in
     * @param format the format we are using
     * @param name the name of the "file"
     * @param length the length of the data we will write
     * @param modificationtime the time of last modification we want stored.
     */
    public outputstream open(
        outputstream    out,
        char            format,
        string          name,
        long            length,
        date            modificationtime)
        throws ioexception
    {
        if (pkout != null)
        {
            throw new illegalstateexception("generator already in open state");
        }

        byte[] encname = strings.toutf8bytearray(name);

        pkout = new bcpgoutputstream(out, packettags.literal_data, length + 2 + encname.length + 4, oldformat);
        
        writeheader(pkout, format, encname, modificationtime.gettime());

        return new wrappedgeneratorstream(pkout, this);
    }
    
    /**
     * open a literal data packet, returning a stream to store the data inside
     * the packet as an indefinite length stream. the stream is written out as a 
     * series of partial packets with a chunk size determined by the size of the
     * passed in buffer.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * <p>
     * <b>note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * 
     * @param out the stream we want the packet in
     * @param format the format we are using
     * @param name the name of the "file"
     * @param modificationtime the time of last modification we want stored.
     * @param buffer the buffer to use for collecting data to put into chunks.
     */
    public outputstream open(
        outputstream    out,
        char            format,
        string          name,
        date            modificationtime,
        byte[]          buffer)
        throws ioexception
    {
        if (pkout != null)
        {
            throw new illegalstateexception("generator already in open state");
        }

        pkout = new bcpgoutputstream(out, packettags.literal_data, buffer);

        byte[] encname = strings.toutf8bytearray(name);

        writeheader(pkout, format, encname, modificationtime.gettime());

        return new wrappedgeneratorstream(pkout, this);
    }
    
    /**
     * open a literal data packet for the passed in file object, returning
     * an output stream for saving the file contents.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * 
     * @param out
     * @param format
     * @param file
     * @return outputstream
     * @throws ioexception
     */
    public outputstream open(
        outputstream    out,
        char            format,
        file            file)
        throws ioexception
    {
        if (pkout != null)
        {
            throw new illegalstateexception("generator already in open state");
        }

        byte[] encname = strings.toutf8bytearray(file.getname());

        pkout = new bcpgoutputstream(out, packettags.literal_data, file.length() + 2 + encname.length + 4, oldformat);
        
        writeheader(pkout, format, encname, file.lastmodified());

        return new wrappedgeneratorstream(pkout, this);
    }
    
    /**
     * close the literal data packet - this is equivalent to calling close on the stream
     * returned by the open() method.
     * 
     * @throws ioexception
     */
    public void close()
        throws ioexception
    {
        if (pkout != null)
        {
            pkout.finish();
            pkout.flush();
            pkout = null;
        }
    }
}
