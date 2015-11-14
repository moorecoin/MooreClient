package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;
import java.io.inputstream;
import java.util.date;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.literaldatapacket;

/**
 * class for processing literal data objects.
 */
public class pgpliteraldata 
{
    public static final char    binary = 'b';
    public static final char    text = 't';
    public static final char    utf8 = 'u';

    /**
     * the special name indicating a "for your eyes only" packet.
     */
    public static final string  console = "_console";
    
    /**
     * the special time for a modification time of "now" or
     * the present time.
     */
    public static final date    now = new date(0l);
    
    literaldatapacket    data;
    
    public pgpliteraldata(
        bcpginputstream    pin)
        throws ioexception
    {
        data  = (literaldatapacket)pin.readpacket();
    }
    
    /**
     * return the format of the data stream - binary or text.
     * 
     * @return int
     */
    public int getformat()
    {
        return data.getformat();
    }
    
    /**
     * return the file name that's associated with the data stream.
     * 
     * @return string
     */
    public string getfilename()
    {
        return data.getfilename();
    }

    /**
     * return the file name as an unintrepreted byte array.
     */
    public byte[] getrawfilename()
    {
        return data.getrawfilename();
    }

    /**
     * return the modification time for the file.
     * 
     * @return the modification time.
     */
    public date getmodificationtime()
    {
        return new date(data.getmodificationtime());
    }
    
    /**
     * return the raw input stream for the data stream.
     * 
     * @return inputstream
     */
    public inputstream getinputstream()
    {
        return data.getinputstream();
    }
    
    /**
     * return the input stream representing the data stream
     * 
     * @return inputstream
     */
    public inputstream getdatastream()
    {
        return this.getinputstream();
    }
}
