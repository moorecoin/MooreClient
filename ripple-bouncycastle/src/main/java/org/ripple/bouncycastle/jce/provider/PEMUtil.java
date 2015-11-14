package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.util.encoders.base64;

public class pemutil
{
    private final string _header1;
    private final string _header2;
    private final string _footer1;
    private final string _footer2;

    pemutil(
        string type)
    {
        _header1 = "-----begin " + type + "-----";
        _header2 = "-----begin x509 " + type + "-----";
        _footer1 = "-----end " + type + "-----";
        _footer2 = "-----end x509 " + type + "-----";
    }

    private string readline(
        inputstream in)
        throws ioexception
    {
        int             c;
        stringbuffer    l = new stringbuffer();

        do
        {
            while (((c = in.read()) != '\r') && c != '\n' && (c >= 0))
            {
                if (c == '\r')
                {
                    continue;
                }

                l.append((char)c);
            }
        }
        while (c >= 0 && l.length() == 0);

        if (c < 0)
        {
            return null;
        }

        return l.tostring();
    }

    asn1sequence readpemobject(
        inputstream  in)
        throws ioexception
    {
        string          line;
        stringbuffer    pembuf = new stringbuffer();

        while ((line = readline(in)) != null)
        {
            if (line.startswith(_header1) || line.startswith(_header2))
            {
                break;
            }
        }

        while ((line = readline(in)) != null)
        {
            if (line.startswith(_footer1) || line.startswith(_footer2))
            {
                break;
            }

            pembuf.append(line);
        }

        if (pembuf.length() != 0)
        {
            asn1primitive o = new asn1inputstream(base64.decode(pembuf.tostring())).readobject();
            if (!(o instanceof asn1sequence))
            {
                throw new ioexception("malformed pem data encountered");
            }

            return (asn1sequence)o;
        }

        return null;
    }
}
