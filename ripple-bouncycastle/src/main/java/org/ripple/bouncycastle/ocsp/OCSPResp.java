package org.ripple.bouncycastle.ocsp;

import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.ocsp.basicocspresponse;
import org.ripple.bouncycastle.asn1.ocsp.ocspobjectidentifiers;
import org.ripple.bouncycastle.asn1.ocsp.ocspresponse;
import org.ripple.bouncycastle.asn1.ocsp.responsebytes;

/**
 * @deprecated use classes in org.bouncycastle.cert.ocsp.
 */
public class ocspresp
{
    private ocspresponse    resp;

    /**
     * @deprecated use classes in org.bouncycastle.cert.ocsp.
     */
    public ocspresp(
        ocspresponse    resp)
    {
        this.resp = resp;
    }

    /**
     * @deprecated use classes in org.bouncycastle.cert.ocsp.
     */
    public ocspresp(
        byte[]          resp)
        throws ioexception
    {
        this(new asn1inputstream(resp));
    }

    /**
     * @deprecated use classes in org.bouncycastle.cert.ocsp.
     */
    public ocspresp(
        inputstream     in)
        throws ioexception
    {
        this(new asn1inputstream(in));
    }

    private ocspresp(
        asn1inputstream ain)
        throws ioexception
    {
        try
        {
            this.resp = ocspresponse.getinstance(ain.readobject());
        }
        catch (illegalargumentexception e)
        {
            throw new ioexception("malformed response: " + e.getmessage());
        }
        catch (classcastexception e)
        {
            throw new ioexception("malformed response: " + e.getmessage());
        }
    }

    public int getstatus()
    {
        return this.resp.getresponsestatus().getvalue().intvalue();
    }

    public object getresponseobject()
        throws ocspexception
    {
        responsebytes   rb = this.resp.getresponsebytes();

        if (rb == null)
        {
            return null;
        }

        if (rb.getresponsetype().equals(ocspobjectidentifiers.id_pkix_ocsp_basic))
        {
            try
            {
                asn1primitive obj = asn1primitive.frombytearray(rb.getresponse().getoctets());
                return new basicocspresp(basicocspresponse.getinstance(obj));
            }
            catch (exception e)
            {
                throw new ocspexception("problem decoding object: " + e, e);
            }
        }

        return rb.getresponse();
    }

    /**
     * return the asn.1 encoded representation of this object.
     */
    public byte[] getencoded()
        throws ioexception
    {
        return resp.getencoded();
    }
    
    public boolean equals(object o)
    {
        if (o == this)
        {
            return true;
        }
        
        if (!(o instanceof ocspresp))
        {
            return false;
        }
        
        ocspresp r = (ocspresp)o;
        
        return resp.equals(r.resp);
    }
    
    public int hashcode()
    {
        return resp.hashcode();
    }
}
