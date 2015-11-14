package org.ripple.bouncycastle.asn1.isismtt.ocsp;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.certificate;

/**
 * isis-mtt-optional: the certificate requested by the client by inserting the
 * retrieveifallowed extension in the request, will be returned in this
 * extension.
 * <p/>
 * isis-mtt-sigg: the signature act allows publishing certificates only then,
 * when the certificate owner gives his explicit permission. accordingly, there
 * may be 锟絥ondownloadable锟?certificates, about which the responder must provide
 * status information, but must not include them in the response. clients may
 * get therefore the following three kind of answers on a single request
 * including the retrieveifallowed extension:
 * <ul>
 * <li> a) the responder supports the extension and is allowed to publish the
 * certificate: requestedcertificate returned including the requested
 * certificate
 * <li>b) the responder supports the extension but is not allowed to publish
 * the certificate: requestedcertificate returned including an empty octet
 * string
 * <li>c) the responder does not support the extension: requestedcertificate is
 * not included in the response
 * </ul>
 * clients requesting retrieveifallowed must be able to handle these cases. if
 * any of the octet string options is used, it must contain the der encoding of
 * the requested certificate.
 * <p/>
 * <pre>
 *            requestedcertificate ::= choice {
 *              certificate certificate,
 *              publickeycertificate [0] explicit octet string,
 *              attributecertificate [1] explicit octet string
 *            }
 * </pre>
 */
public class requestedcertificate
    extends asn1object
    implements asn1choice
{
    public static final int certificate = -1;
    public static final int publickeycertificate = 0;
    public static final int attributecertificate = 1;

    private certificate cert;
    private byte[] publickeycert;
    private byte[] attributecert;

    public static requestedcertificate getinstance(object obj)
    {
        if (obj == null || obj instanceof requestedcertificate)
        {
            return (requestedcertificate)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new requestedcertificate(certificate.getinstance(obj));
        }
        if (obj instanceof asn1taggedobject)
        {
            return new requestedcertificate((asn1taggedobject)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    public static requestedcertificate getinstance(asn1taggedobject obj, boolean explicit)
    {
        if (!explicit)
        {
            throw new illegalargumentexception("choice item must be explicitly tagged");
        }

        return getinstance(obj.getobject());
    }

    private requestedcertificate(asn1taggedobject tagged)
    {
        if (tagged.gettagno() == publickeycertificate)
        {
            publickeycert = asn1octetstring.getinstance(tagged, true).getoctets();
        }
        else if (tagged.gettagno() == attributecertificate)
        {
            attributecert = asn1octetstring.getinstance(tagged, true).getoctets();
        }
        else
        {
            throw new illegalargumentexception("unknown tag number: " + tagged.gettagno());
        }
    }

    /**
     * constructor from a given details.
     * <p/>
     * only one parameter can be given. all other must be <code>null</code>.
     *
     * @param certificate          given as certificate
     */
    public requestedcertificate(certificate certificate)
    {
        this.cert = certificate;
    }

    public requestedcertificate(int type, byte[] certificateoctets)
    {
        this(new dertaggedobject(type, new deroctetstring(certificateoctets)));
    }

    public int gettype()
    {
        if (cert != null)
        {
            return certificate;
        }
        if (publickeycert != null)
        {
            return publickeycertificate;
        }
        return attributecertificate;
    }

    public byte[] getcertificatebytes()
    {
        if (cert != null)
        {
            try
            {
                return cert.getencoded();
            }
            catch (ioexception e)
            {
                throw new illegalstateexception("can't decode certificate: " + e);
            }
        }
        if (publickeycert != null)
        {
            return publickeycert;
        }
        return attributecert;
    }
    
    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *            requestedcertificate ::= choice {
     *              certificate certificate,
     *              publickeycertificate [0] explicit octet string,
     *              attributecertificate [1] explicit octet string
     *            }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        if (publickeycert != null)
        {
            return new dertaggedobject(0, new deroctetstring(publickeycert));
        }
        if (attributecert != null)
        {
            return new dertaggedobject(1, new deroctetstring(attributecert));
        }
        return cert.toasn1primitive();
    }
}
