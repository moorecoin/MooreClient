package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.hashtable;

import org.ripple.bouncycastle.util.integers;

/**
 * rfc 5764 dtls extension to establish keys for srtp.
 */
public class tlssrtputils
{

    public static final integer ext_use_srtp = integers.valueof(extensiontype.use_srtp);

    public static void addusesrtpextension(hashtable extensions, usesrtpdata usesrtpdata)
        throws ioexception
    {

        extensions.put(ext_use_srtp, createusesrtpextension(usesrtpdata));
    }

    public static usesrtpdata getusesrtpextension(hashtable extensions)
        throws ioexception
    {

        if (extensions == null)
        {
            return null;
        }
        byte[] extensionvalue = (byte[])extensions.get(ext_use_srtp);
        if (extensionvalue == null)
        {
            return null;
        }
        return readusesrtpextension(extensionvalue);
    }

    public static byte[] createusesrtpextension(usesrtpdata usesrtpdata)
        throws ioexception
    {

        if (usesrtpdata == null)
        {
            throw new illegalargumentexception("'usesrtpdata' cannot be null");
        }

        bytearrayoutputstream buf = new bytearrayoutputstream();

        // srtpprotectionprofiles
        int[] protectionprofiles = usesrtpdata.getprotectionprofiles();
        tlsutils.writeuint16(2 * protectionprofiles.length, buf);
        tlsutils.writeuint16array(protectionprofiles, buf);

        // srtp_mki
        tlsutils.writeopaque8(usesrtpdata.getmki(), buf);

        return buf.tobytearray();
    }

    public static usesrtpdata readusesrtpextension(byte[] extensionvalue)
        throws ioexception
    {

        if (extensionvalue == null)
        {
            throw new illegalargumentexception("'extensionvalue' cannot be null");
        }

        bytearrayinputstream buf = new bytearrayinputstream(extensionvalue);

        // srtpprotectionprofiles
        int length = tlsutils.readuint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }
        int[] protectionprofiles = tlsutils.readuint16array(length / 2, buf);

        // srtp_mki
        byte[] mki = tlsutils.readopaque8(buf);

        tlsprotocol.assertempty(buf);

        return new usesrtpdata(protectionprofiles, mki);
    }
}
