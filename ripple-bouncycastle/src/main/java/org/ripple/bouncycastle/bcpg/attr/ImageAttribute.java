package org.ripple.bouncycastle.bcpg.attr;

import org.ripple.bouncycastle.bcpg.userattributesubpacket;
import org.ripple.bouncycastle.bcpg.userattributesubpackettags;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * basic type for a image attribute packet.
 */
public class imageattribute 
    extends userattributesubpacket
{
    public static final int jpeg = 1;

    private static final byte[] zeroes = new byte[12];

    private int     hdrlength;
    private int     version;
    private int     encoding;
    private byte[]  imagedata;
    
    public imageattribute(
        byte[]    data)
    {
        super(userattributesubpackettags.image_attribute, data);
        
        hdrlength = ((data[1] & 0xff) << 8) | (data[0] & 0xff);
        version = data[2] & 0xff;
        encoding = data[3] & 0xff;
        
        imagedata = new byte[data.length - hdrlength];
        system.arraycopy(data, hdrlength, imagedata, 0, imagedata.length);
    }

    public imageattribute(
        int imagetype,
        byte[] imagedata)
    {
        this(tobytearray(imagetype, imagedata));
    }

    private static byte[] tobytearray(int imagetype, byte[] imagedata)
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();

        try
        {
            bout.write(0x10); bout.write(0x00); bout.write(0x01);
            bout.write(imagetype);
            bout.write(zeroes);
            bout.write(imagedata);
        }
        catch (ioexception e)
        {
            throw new runtimeexception("unable to encode to byte array!");
        }

        return bout.tobytearray();
    }

    public int version()
    {
        return version;
    }
    
    public int getencoding()
    {
        return encoding;
    }
    
    public byte[] getimagedata()
    {
        return imagedata;
    }
}
