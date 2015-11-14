package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * parsing and encoding of a <i>certificaterequest</i> struct from rfc 4346.
 * <p/>
 * <pre>
 * struct {
 *     clientcertificatetype certificate_types<1..2^8-1>;
 *     distinguishedname certificate_authorities<3..2^16-1>;
 * } certificaterequest;
 * </pre>
 *
 * @see clientcertificatetype
 * @see x500name
 */
public class certificaterequest
{
    private short[] certificatetypes;
    private vector certificateauthorities;

    /*
     * todo rfc 5264 7.4.4 a list of the hash/signature algorithm pairs that the server is able to
     * verify, listed in descending order of preference.
     */

    /**
     * @param certificatetypes       see {@link clientcertificatetype} for valid constants.
     * @param certificateauthorities a {@link vector} of {@link x500name}.
     */
    public certificaterequest(short[] certificatetypes, vector certificateauthorities)
    {
        this.certificatetypes = certificatetypes;
        this.certificateauthorities = certificateauthorities;
    }

    /**
     * @return an array of certificate types
     * @see {@link clientcertificatetype}
     */
    public short[] getcertificatetypes()
    {
        return certificatetypes;
    }

    /**
     * @return a {@link vector} of {@link x500name}
     */
    public vector getcertificateauthorities()
    {
        return certificateauthorities;
    }

    /**
     * encode this {@link certificaterequest} to an {@link outputstream}.
     *
     * @param output the {@link outputstream} to encode to.
     * @throws ioexception
     */
    public void encode(outputstream output)
        throws ioexception
    {

        if (certificatetypes == null || certificatetypes.length == 0)
        {
            tlsutils.writeuint8((short)0, output);
        }
        else
        {
            tlsutils.writeuint8((short)certificatetypes.length, output);
            tlsutils.writeuint8array(certificatetypes, output);
        }

        if (certificateauthorities == null || certificateauthorities.isempty())
        {
            tlsutils.writeuint16(0, output);
        }
        else
        {

            vector encdns = new vector(certificateauthorities.size());
            int totallength = 0;
            for (int i = 0; i < certificateauthorities.size(); ++i)
            {
                x500name authoritydn = (x500name)certificateauthorities.elementat(i);
                byte[] encdn = authoritydn.getencoded(asn1encoding.der);
                encdns.addelement(encdn);
                totallength += encdn.length;
            }

            tlsutils.writeuint16(totallength, output);

            for (int i = 0; i < encdns.size(); ++i)
            {
                byte[] encdn = (byte[])encdns.elementat(i);
                output.write(encdn);
            }
        }
    }

    /**
     * parse a {@link certificaterequest} from an {@link inputstream}.
     *
     * @param input the {@link inputstream} to parse from.
     * @return a {@link certificaterequest} object.
     * @throws ioexception
     */
    public static certificaterequest parse(inputstream input)
        throws ioexception
    {
        int numtypes = tlsutils.readuint8(input);
        short[] certificatetypes = new short[numtypes];
        for (int i = 0; i < numtypes; ++i)
        {
            certificatetypes[i] = tlsutils.readuint8(input);
        }

        byte[] authorities = tlsutils.readopaque16(input);

        vector authoritydns = new vector();

        bytearrayinputstream bis = new bytearrayinputstream(authorities);
        while (bis.available() > 0)
        {
            byte[] dnbytes = tlsutils.readopaque16(bis);
            authoritydns.addelement(x500name.getinstance(asn1primitive.frombytearray(dnbytes)));
        }

        return new certificaterequest(certificatetypes, authoritydns);
    }
}
