package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.security.cert.certificateencodingexception;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509certificate;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.x509.certificate;
import org.ripple.bouncycastle.asn1.x509.certificatepair;
import org.ripple.bouncycastle.jce.provider.x509certificateobject;

/**
 * this class contains a cross certificate pair. cross certificates pairs may
 * contain two cross signed certificates from two cas. a certificate from the
 * other ca to this ca is contained in the forward certificate, the certificate
 * from this ca to the other ca is contained in the reverse certificate.
 */
public class x509certificatepair
{
    private x509certificate forward;
    private x509certificate reverse;

    /**
     * constructor.
     *
     * @param forward certificate from the other ca to this ca.
     * @param reverse certificate from this ca to the other ca.
     */
    public x509certificatepair(
        x509certificate forward,
        x509certificate reverse)
    {
        this.forward = forward;
        this.reverse = reverse;
    }

    /**
     * constructor from a asn.1 certificatepair structure.
     *
     * @param pair the <code>certificatepair</code> asn.1 object.
     */
    public x509certificatepair(
        certificatepair pair)
        throws certificateparsingexception
    {
        if (pair.getforward() != null)
        {
            this.forward = new x509certificateobject(pair.getforward());
        }
        if (pair.getreverse() != null)
        {
            this.reverse = new x509certificateobject(pair.getreverse());
        }
    }
    
    public byte[] getencoded()
        throws certificateencodingexception
    {
        certificate f = null;
        certificate r = null;
        try
        {
            if (forward != null)
            {
                f = certificate.getinstance(new asn1inputstream(
                    forward.getencoded()).readobject());
                if (f == null)
                {
                    throw new certificateencodingexception("unable to get encoding for forward");
                }
            }
            if (reverse != null)
            {
                r = certificate.getinstance(new asn1inputstream(
                    reverse.getencoded()).readobject());
                if (r == null)
                {
                    throw new certificateencodingexception("unable to get encoding for reverse");
                }
            }
            return new certificatepair(f, r).getencoded(asn1encoding.der);
        }
        catch (illegalargumentexception e)
        {
            throw new extcertificateencodingexception(e.tostring(), e);
        }
        catch (ioexception e)
        {
            throw new extcertificateencodingexception(e.tostring(), e);
        }
    }

    /**
     * returns the certificate from the other ca to this ca.
     *
     * @return returns the forward certificate.
     */
    public x509certificate getforward()
    {
        return forward;
    }

    /**
     * return the certificate from this ca to the other ca.
     *
     * @return returns the reverse certificate.
     */
    public x509certificate getreverse()
    {
        return reverse;
    }

    public boolean equals(object o)
    {
        if (o == null)
        {
            return false;
        }
        if (!(o instanceof x509certificatepair))
        {
            return false;
        }
        x509certificatepair pair = (x509certificatepair)o;
        boolean equalreverse = true;
        boolean equalforward = true;
        if (forward != null)
        {
            equalforward = this.forward.equals(pair.forward);
        }
        else
        {
            if (pair.forward != null)
            {
                equalforward = false;
            }
        }
        if (reverse != null)
        {
            equalreverse = this.reverse.equals(pair.reverse);
        }
        else
        {
            if (pair.reverse != null)
            {
                equalreverse = false;
            }
        }
        return equalforward && equalreverse;
    }

    public int hashcode()
    {
        int hash = -1;
        if (forward != null)
        {
            hash ^= forward.hashcode();
        }
        if (reverse != null)
        {
            hash *= 17;
            hash ^= reverse.hashcode();
        }
        return hash;
    }
}
