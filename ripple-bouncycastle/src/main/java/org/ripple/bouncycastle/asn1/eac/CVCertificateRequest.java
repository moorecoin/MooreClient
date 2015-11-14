package org.ripple.bouncycastle.asn1.eac;

import java.io.ioexception;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1parsingexception;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.bertags;
import org.ripple.bouncycastle.asn1.derapplicationspecific;
import org.ripple.bouncycastle.asn1.deroctetstring;

//import java.math.biginteger;


public class cvcertificaterequest
    extends asn1object
{
    private certificatebody certificatebody;

    private byte[] innersignature = null;
    private byte[] outersignature = null;

    private int valid;

    private static int bodyvalid = 0x01;
    private static int signvalid = 0x02;

    private cvcertificaterequest(derapplicationspecific request)
        throws ioexception
    {
        if (request.getapplicationtag() == eactags.authentification_data)
        {
            asn1sequence seq = asn1sequence.getinstance(request.getobject(bertags.sequence));

            initcertbody(derapplicationspecific.getinstance(seq.getobjectat(0)));

            outersignature = derapplicationspecific.getinstance(seq.getobjectat(seq.size() - 1)).getcontents();
        }
        else
        {
            initcertbody(request);
        }
    }

    private void initcertbody(derapplicationspecific request)
        throws ioexception
    {
        if (request.getapplicationtag() == eactags.cardholder_certificate)
        {
            asn1sequence seq = asn1sequence.getinstance(request.getobject(bertags.sequence));
            for (enumeration en = seq.getobjects(); en.hasmoreelements();)
            {
                derapplicationspecific obj = derapplicationspecific.getinstance(en.nextelement());
                switch (obj.getapplicationtag())
                {
                case eactags.certificate_content_template:
                    certificatebody = certificatebody.getinstance(obj);
                    valid |= bodyvalid;
                    break;
                case eactags.static_internal_authentification_one_step:
                    innersignature = obj.getcontents();
                    valid |= signvalid;
                    break;
                default:
                    throw new ioexception("invalid tag, not an cv certificate request element:" + obj.getapplicationtag());
                }
            }
        }
        else
        {
            throw new ioexception("not a cardholder_certificate in request:" + request.getapplicationtag());
        }
    }

    public static cvcertificaterequest getinstance(object obj)
    {
        if (obj instanceof cvcertificaterequest)
        {
            return (cvcertificaterequest)obj;
        }
        else if (obj != null)
        {
            try
            {
                return new cvcertificaterequest(derapplicationspecific.getinstance(obj));
            }
            catch (ioexception e)
            {
                throw new asn1parsingexception("unable to parse data: " + e.getmessage(), e);
            }
        }

        return null;
    }

    asn1objectidentifier signoid = null;
    asn1objectidentifier keyoid = null;

    public static byte[] zeroarray = new byte[]{0};


    string strcertificateholderreference;

    byte[] encodedauthorityreference;

    int profileid;

    /**
     * returns the body of the certificate template
     *
     * @return the body.
     */
    public certificatebody getcertificatebody()
    {
        return certificatebody;
    }

    /**
     * return the public key data object carried in the request
     * @return  the public key
     */
    public publickeydataobject getpublickey()
    {
        return certificatebody.getpublickey();
    }

    public byte[] getinnersignature()
    {
        return innersignature;
    }

    public byte[] getoutersignature()
    {
        return outersignature;
    }

    byte[] certificate = null;
    protected string oversignerreference = null;

    public boolean hasoutersignature()
    {
        return outersignature != null;
    }

    byte[] encoded;

    publickeydataobject iso7816pubkey = null;

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certificatebody);

        try
        {
            v.add(new derapplicationspecific(false, eactags.static_internal_authentification_one_step, new deroctetstring(innersignature)));
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unable to convert signature!");
        }

        return new derapplicationspecific(eactags.cardholder_certificate, v);
    }
}
