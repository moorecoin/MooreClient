package org.ripple.bouncycastle.util.io.pem;

import java.io.bufferedwriter;
import java.io.ioexception;
import java.io.writer;
import java.util.iterator;

import org.ripple.bouncycastle.util.encoders.base64;

/**
 * a generic pem writer, based on rfc 1421
 */
public class pemwriter
    extends bufferedwriter
{
    private static final int line_length = 64;

    private final int nllength;
    private char[]  buf = new char[line_length];

    /**
     * base constructor.
     *
     * @param out output stream to use.
     */
    public pemwriter(writer out)
    {
        super(out);

        string nl = system.getproperty("line.separator");
        if (nl != null)
        {
            nllength = nl.length();
        }
        else
        {
            nllength = 2;
        }
    }

    /**
     * return the number of bytes or characters required to contain the
     * passed in object if it is pem encoded.
     *
     * @param obj pem object to be output
     * @return an estimate of the number of bytes
     */
    public int getoutputsize(pemobject obj)
    {
        // begin and end boundaries.
        int size = (2 * (obj.gettype().length() + 10 + nllength)) + 6 + 4;

        if (!obj.getheaders().isempty())
        {
            for (iterator it = obj.getheaders().iterator(); it.hasnext();)
            {
                pemheader hdr = (pemheader)it.next();

                size += hdr.getname().length() + ": ".length() + hdr.getvalue().length() + nllength;
            }

            size += nllength;
        }

        // base64 encoding
        int datalen = ((obj.getcontent().length + 2) / 3) * 4;
        
        size += datalen + (((datalen + line_length - 1) / line_length) * nllength);

        return size;
    }
    
    public void writeobject(pemobjectgenerator objgen)
        throws ioexception
    {
        pemobject obj = objgen.generate();

        writepreencapsulationboundary(obj.gettype());

        if (!obj.getheaders().isempty())
        {
            for (iterator it = obj.getheaders().iterator(); it.hasnext();)
            {
                pemheader hdr = (pemheader)it.next();

                this.write(hdr.getname());
                this.write(": ");
                this.write(hdr.getvalue());
                this.newline();
            }

            this.newline();
        }
        
        writeencoded(obj.getcontent());
        writepostencapsulationboundary(obj.gettype());
    }

    private void writeencoded(byte[] bytes)
        throws ioexception
    {
        bytes = base64.encode(bytes);

        for (int i = 0; i < bytes.length; i += buf.length)
        {
            int index = 0;

            while (index != buf.length)
            {
                if ((i + index) >= bytes.length)
                {
                    break;
                }
                buf[index] = (char)bytes[i + index];
                index++;
            }
            this.write(buf, 0, index);
            this.newline();
        }
    }

    private void writepreencapsulationboundary(
        string type)
        throws ioexception
    {
        this.write("-----begin " + type + "-----");
        this.newline();
    }

    private void writepostencapsulationboundary(
        string type)
        throws ioexception
    {
        this.write("-----end " + type + "-----");
        this.newline();
    }
}
