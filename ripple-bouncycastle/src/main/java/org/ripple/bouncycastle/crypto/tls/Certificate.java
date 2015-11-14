package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;

/**
 * parsing and encoding of a <i>certificate</i> struct from rfc 4346.
 * <p/>
 * <pre>
 * opaque asn.1cert<2^24-1>;
 *
 * struct {
 *     asn.1cert certificate_list<0..2^24-1>;
 * } certificate;
 * </pre>
 *
 * @see org.ripple.bouncycastle.asn1.x509.certificate
 */
public class certificate
{

    public static final certificate empty_chain = new certificate(
        new org.ripple.bouncycastle.asn1.x509.certificate[0]);

    protected org.ripple.bouncycastle.asn1.x509.certificate[] certificatelist;

    public certificate(org.ripple.bouncycastle.asn1.x509.certificate[] certificatelist)
    {
        if (certificatelist == null)
        {
            throw new illegalargumentexception("'certificatelist' cannot be null");
        }

        this.certificatelist = certificatelist;
    }

    /**
     * @deprecated use {@link #getcertificatelist()} instead
     */
    public org.ripple.bouncycastle.asn1.x509.certificate[] getcerts()
    {
        return clone(certificatelist);
    }

    /**
     * @return an array of {@link org.ripple.bouncycastle.asn1.x509.certificate} representing a certificate
     *         chain.
     */
    public org.ripple.bouncycastle.asn1.x509.certificate[] getcertificatelist()
    {
        return clone(certificatelist);
    }

    public org.ripple.bouncycastle.asn1.x509.certificate getcertificateat(int index)
    {
        return certificatelist[index];
    }

    public int getlength()
    {
        return certificatelist.length;
    }

    /**
     * @return <code>true</code> if this certificate chain contains no certificates, or
     *         <code>false</code> otherwise.
     */
    public boolean isempty()
    {
        return certificatelist.length == 0;
    }

    /**
     * encode this {@link certificate} to an {@link outputstream}.
     *
     * @param output the {@link outputstream} to encode to.
     * @throws ioexception
     */
    public void encode(outputstream output)
        throws ioexception
    {
        vector enccerts = new vector(this.certificatelist.length);
        int totallength = 0;
        for (int i = 0; i < this.certificatelist.length; ++i)
        {
            byte[] enccert = certificatelist[i].getencoded(asn1encoding.der);
            enccerts.addelement(enccert);
            totallength += enccert.length + 3;
        }

        tlsutils.writeuint24(totallength, output);

        for (int i = 0; i < enccerts.size(); ++i)
        {
            byte[] enccert = (byte[])enccerts.elementat(i);
            tlsutils.writeopaque24(enccert, output);
        }
    }

    /**
     * parse a {@link certificate} from an {@link inputstream}.
     *
     * @param input the {@link inputstream} to parse from.
     * @return a {@link certificate} object.
     * @throws ioexception
     */
    public static certificate parse(inputstream input)
        throws ioexception
    {
        org.ripple.bouncycastle.asn1.x509.certificate[] certs;
        int left = tlsutils.readuint24(input);
        if (left == 0)
        {
            return empty_chain;
        }
        vector tmp = new vector();
        while (left > 0)
        {
            int size = tlsutils.readuint24(input);
            left -= 3 + size;

            byte[] buf = tlsutils.readfully(size, input);

            bytearrayinputstream bis = new bytearrayinputstream(buf);
            asn1primitive asn1 = new asn1inputstream(bis).readobject();
            tlsprotocol.assertempty(bis);

            tmp.addelement(org.ripple.bouncycastle.asn1.x509.certificate.getinstance(asn1));
        }
        certs = new org.ripple.bouncycastle.asn1.x509.certificate[tmp.size()];
        for (int i = 0; i < tmp.size(); i++)
        {
            certs[i] = (org.ripple.bouncycastle.asn1.x509.certificate)tmp.elementat(i);
        }
        return new certificate(certs);
    }

    private org.ripple.bouncycastle.asn1.x509.certificate[] clone(org.ripple.bouncycastle.asn1.x509.certificate[] list)
    {
        org.ripple.bouncycastle.asn1.x509.certificate[] rv = new org.ripple.bouncycastle.asn1.x509.certificate[list.length];

        system.arraycopy(list, 0, rv, 0, rv.length);

        return rv;
    }
}
