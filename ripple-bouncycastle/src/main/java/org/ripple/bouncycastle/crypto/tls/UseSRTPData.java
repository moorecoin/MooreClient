package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 5764 4.1.1
 */
public class usesrtpdata
{

    private int[] protectionprofiles;
    private byte[] mki;

    /**
     * @param protectionprofiles see {@link srtpprotectionprofile} for valid constants.
     * @param mki                valid lengths from 0 to 255.
     */
    public usesrtpdata(int[] protectionprofiles, byte[] mki)
    {

        if (protectionprofiles == null || protectionprofiles.length < 1
            || protectionprofiles.length >= (1 << 15))
        {
            throw new illegalargumentexception(
                "'protectionprofiles' must have length from 1 to (2^15 - 1)");
        }

        if (mki == null)
        {
            mki = tlsutils.empty_bytes;
        }
        else if (mki.length > 255)
        {
            throw new illegalargumentexception("'mki' cannot be longer than 255 bytes");
        }

        this.protectionprofiles = protectionprofiles;
        this.mki = mki;
    }

    /**
     * @return see {@link srtpprotectionprofile} for valid constants.
     */
    public int[] getprotectionprofiles()
    {
        return protectionprofiles;
    }

    /**
     * @return valid lengths from 0 to 255.
     */
    public byte[] getmki()
    {
        return mki;
    }
}
