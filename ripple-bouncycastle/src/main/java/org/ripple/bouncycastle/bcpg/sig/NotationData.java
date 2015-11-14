package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;
import org.ripple.bouncycastle.util.strings;

import java.io.bytearrayoutputstream;

/**
 * class provided a notationdata object according to
 * rfc2440, chapter 5.2.3.15. notation data
 */
public class notationdata
    extends signaturesubpacket
{
    public static final int header_flag_length = 4;
    public static final int header_name_length = 2;
    public static final int header_value_length = 2;

    public notationdata(boolean critical, byte[] data)
    {
        super(signaturesubpackettags.notation_data, critical, data);
    }

    public notationdata(
        boolean critical,
        boolean humanreadable,
        string notationname,
        string notationvalue)
    {
        super(signaturesubpackettags.notation_data, critical, createdata(humanreadable, notationname, notationvalue));
    }

    private static byte[] createdata(boolean humanreadable, string notationname, string notationvalue)
    {
        bytearrayoutputstream out = new bytearrayoutputstream();

//        (4 octets of flags, 2 octets of name length (m),
//        2 octets of value length (n),
//        m octets of name data,
//        n octets of value data)

        // flags
        out.write(humanreadable ? 0x80 : 0x00);
        out.write(0x0);
        out.write(0x0);
        out.write(0x0);

        byte[] namedata, valuedata = null;
        int namelength, valuelength;

        namedata = strings.toutf8bytearray(notationname);
        namelength = math.min(namedata.length, 0xff);

        valuedata = strings.toutf8bytearray(notationvalue);
        valuelength = math.min(valuedata.length, 0xff);

        // name length
        out.write((namelength >>> 8) & 0xff);
        out.write((namelength >>> 0) & 0xff);

        // value length
        out.write((valuelength >>> 8) & 0xff);
        out.write((valuelength >>> 0) & 0xff);

        // name
        out.write(namedata, 0, namelength);

        // value
        out.write(valuedata, 0, valuelength);

        return out.tobytearray();
    }

    public boolean ishumanreadable()
    {
        return data[0] == (byte)0x80;
    }

    public string getnotationname()
    {
        int namelength = ((data[header_flag_length] << 8) + (data[header_flag_length + 1] << 0));

        byte bname[] = new byte[namelength];
        system.arraycopy(data, header_flag_length + header_name_length + header_value_length, bname, 0, namelength);

        return strings.fromutf8bytearray(bname);
    }

    public string getnotationvalue()
    {
        return strings.fromutf8bytearray(getnotationvaluebytes());
    }

    public byte[] getnotationvaluebytes()
    {
        int namelength = ((data[header_flag_length] << 8) + (data[header_flag_length + 1] << 0));
        int valuelength = ((data[header_flag_length + header_name_length] << 8) + (data[header_flag_length + header_name_length + 1] << 0));

        byte bvalue[] = new byte[valuelength];
        system.arraycopy(data, header_flag_length + header_name_length + header_value_length + namelength, bvalue, 0, valuelength);
        return bvalue;
    }
}
