package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

import org.ripple.bouncycastle.util.strings;

/**
 * generic literal data packet.
 */
public class literaldatapacket 
    extends inputstreampacket
{
    int     format;
    byte[]  filename;
    long    moddate;
    
    literaldatapacket(
        bcpginputstream    in)
        throws ioexception
    {
        super(in);
        
        format = in.read();    
        int    l = in.read();
        
        filename = new byte[l];
        for (int i = 0; i != filename.length; i++)
        {
            filename[i] = (byte)in.read();
        }

        moddate = ((long)in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
    }
    
    /**
     * return the format tag value.
     * 
     * @return format tag value.
     */
    public int getformat()
    {
        return format;
    }

    /**
     * return the modification time of the file in milli-seconds.
     * 
     * @return the modification time in millis
     */
    public long getmodificationtime()
    {
        return moddate * 1000l;
    }
    
    /**
     * @return filename
     */
    public string getfilename()
    {
        return strings.fromutf8bytearray(filename);
    }

    public byte[] getrawfilename()
    {
        byte[] tmp = new byte[filename.length];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = filename[i];
        }

        return tmp;
    }
}
