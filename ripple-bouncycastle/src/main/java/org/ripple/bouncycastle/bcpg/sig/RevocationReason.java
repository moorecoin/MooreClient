package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;
import org.ripple.bouncycastle.util.strings;

/**
 * represents revocation reason openpgp signature sub packet.
 */
public class revocationreason extends signaturesubpacket
{
    public revocationreason(boolean iscritical, byte[] data)
    {
        super(signaturesubpackettags.revocation_reason, iscritical, data);
    }

    public revocationreason(boolean iscritical, byte reason, string description)
    {
        super(signaturesubpackettags.revocation_reason, iscritical, createdata(reason, description));
    }

    private static byte[] createdata(byte reason, string description)
    {
        byte[] descriptionbytes = strings.toutf8bytearray(description);
        byte[] data = new byte[1 + descriptionbytes.length];

        data[0] = reason;
        system.arraycopy(descriptionbytes, 0, data, 1, descriptionbytes.length);

        return data;
    }

    public byte getrevocationreason()
    {
        return getdata()[0];
    }

    public string getrevocationdescription()
    {
        byte[] data = getdata();
        if (data.length == 1)
        {
            return "";
        }

        byte[] description = new byte[data.length - 1];
        system.arraycopy(data, 1, description, 0, description.length);

        return strings.fromutf8bytearray(description);
    }
}
