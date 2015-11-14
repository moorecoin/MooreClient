package org.ripple.bouncycastle.asn1.eac;


import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1parsingexception;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derapplicationspecific;
import org.ripple.bouncycastle.asn1.deroctetstring;


/**
 * an iso7816certificate structure.
 * <p/>
 * <pre>
 *  certificate ::= sequence {
 *      certificatebody         iso7816certificatebody,
 *      signature               der application specific
 *  }
 * </pre>
 */
public class cvcertificate
    extends asn1object
{
    private certificatebody certificatebody;
    private byte[] signature;
    private int valid;
    private static int bodyvalid = 0x01;
    private static int signvalid = 0x02;
    public static final byte version_1 = 0x0;

    public static string referenceencoding = "iso-8859-1";

    /**
     * sets the values of the certificate (body and signature).
     *
     * @param appspe is a derapplicationspecific object containing body and signature.
     * @throws ioexception if tags or value are incorrect.
     */
    private void setprivatedata(derapplicationspecific appspe)
        throws ioexception
    {
        valid = 0;
        if (appspe.getapplicationtag() == eactags.cardholder_certificate)
        {
            asn1inputstream content = new asn1inputstream(appspe.getcontents());
            asn1primitive tmpobj;
            while ((tmpobj = content.readobject()) != null)
            {
                derapplicationspecific aspe;
                if (tmpobj instanceof derapplicationspecific)
                {
                    aspe = (derapplicationspecific)tmpobj;
                    switch (aspe.getapplicationtag())
                    {
                    case eactags.certificate_content_template:
                        certificatebody = certificatebody.getinstance(aspe);
                        valid |= bodyvalid;
                        break;
                    case eactags.static_internal_authentification_one_step:
                        signature = aspe.getcontents();
                        valid |= signvalid;
                        break;
                    default:
                        throw new ioexception("invalid tag, not an iso7816certificatestructure :" + aspe.getapplicationtag());
                    }
                }
                else
                {
                    throw new ioexception("invalid object, not an iso7816certificatestructure");
                }
            }
        }
        else
        {
            throw new ioexception("not a cardholder_certificate :" + appspe.getapplicationtag());
        }
    }

    /**
     * create an iso7816certificate structure from an asn1inputstream.
     *
     * @param ais the byte stream to parse.
     * @return the iso7816certificatestructure represented by the byte stream.
     * @throws ioexception if there is a problem parsing the data.
     */
    public cvcertificate(asn1inputstream ais)
        throws ioexception
    {
        initfrom(ais);
    }

    private void initfrom(asn1inputstream ais)
        throws ioexception
    {
        asn1primitive obj;
        while ((obj = ais.readobject()) != null)
        {
            if (obj instanceof derapplicationspecific)
            {
                setprivatedata((derapplicationspecific)obj);
            }
            else
            {
                throw new ioexception("invalid input stream for creating an iso7816certificatestructure");
            }
        }
    }

    /**
     * create an iso7816certificate structure from a derapplicationspecific.
     *
     * @param appspe the derapplicationspecific object.
     * @return the iso7816certificatestructure represented by the derapplicationspecific object.
     * @throws ioexception if there is a problem parsing the data.
     */
    private cvcertificate(derapplicationspecific appspe)
        throws ioexception
    {
        setprivatedata(appspe);
    }

    /**
     * create an iso7816certificate structure from a body and its signature.
     *
     * @param body the iso7816certificatebody object containing the body.
     * @param signature   the byte array containing the signature
     * @return the iso7816certificatestructure
     * @throws ioexception if there is a problem parsing the data.
     */
    public cvcertificate(certificatebody body, byte[] signature)
        throws ioexception
    {
        certificatebody = body;
        this.signature = signature;
        // patch remi
        valid |= bodyvalid;
        valid |= signvalid;
    }

    /**
     * create an iso7816certificate structure from an object.
     *
     * @param obj the object to extract the certificate from.
     * @return the iso7816certificatestructure represented by the byte stream.
     * @throws ioexception if there is a problem parsing the data.
     */
    public static cvcertificate getinstance(object obj)
    {
        if (obj instanceof cvcertificate)
        {
            return (cvcertificate)obj;
        }
        else if (obj != null)
        {
            try
            {
                return new cvcertificate(derapplicationspecific.getinstance(obj));
            }
            catch (ioexception e)
            {
                throw new asn1parsingexception("unable to parse data: " + e.getmessage(), e);
            }
        }

        return null;
    }

    /**
     * gives the signature of the whole body. type of signature is given in
     * the iso7816certificatebody.iso7816publickey.asn1objectidentifier
     *
     * @return the signature of the body.
     */
    public byte[] getsignature()
    {
        return signature;
    }

    /**
     * gives the body of the certificate.
     *
     * @return the body.
     */
    public certificatebody getbody()
    {
        return certificatebody;
    }

    /**
     * @see org.ripple.bouncycastle.asn1.asn1object#toasn1primitive()
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (valid != (signvalid | bodyvalid))
        {
            return null;
        }
        v.add(certificatebody);

        try
        {
            v.add(new derapplicationspecific(false, eactags.static_internal_authentification_one_step, new deroctetstring(signature)));
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unable to convert signature!");
        }

        return new derapplicationspecific(eactags.cardholder_certificate, v);
    }

    /**
     * @return the holder authorization and role (cvca, dv, is).
     */
    public asn1objectidentifier getholderauthorization()
        throws ioexception
    {
        certificateholderauthorization cha = certificatebody.getcertificateholderauthorization();
        return cha.getoid();
    }

    /**
     * @return the date of the certificate generation
     */
    public packeddate geteffectivedate()
        throws ioexception
    {
        return certificatebody.getcertificateeffectivedate();
    }


    /**
     * @return the type of certificate (request or profile)
     *         value is either iso7816certificatebody.profiletype
     *         or iso7816certificatebody.requesttype. any other value
     *         is not valid.
     */
    public int getcertificatetype()
    {
        return this.certificatebody.getcertificatetype();
    }

    /**
     * @return the date of the certificate generation
     */
    public packeddate getexpirationdate()
        throws ioexception
    {
        return certificatebody.getcertificateexpirationdate();
    }


    /**
     * return a bits field coded on one byte. for signification of the
     * several bit see iso7816certificateholderauthorization
     *
     * @return role and access rigth
     * @throws ioexception
     * @see certificateholderauthorization
     */
    public int getrole()
        throws ioexception
    {
        certificateholderauthorization cha = certificatebody.getcertificateholderauthorization();
        return cha.getaccessrights();
    }

    /**
     * @return the authority reference field of the certificate
     * @throws ioexception
     */
    public certificationauthorityreference getauthorityreference()
        throws ioexception
    {
        return certificatebody.getcertificationauthorityreference();
    }

    /**
     * @return the holder reference field of the certificate
     * @throws ioexception
     */
    public certificateholderreference getholderreference()
        throws ioexception
    {
        return certificatebody.getcertificateholderreference();
    }

    /**
     * @return the bits corresponding to the role intented for the certificate
     *         see iso7816certificateholderauthorization static int for values
     * @throws ioexception
     */
    public int getholderauthorizationrole()
        throws ioexception
    {
        int rights = certificatebody.getcertificateholderauthorization().getaccessrights();
        return rights & 0xc0;
    }

    /**
     * @return the bits corresponding the authorizations contained in the certificate
     *         see iso7816certificateholderauthorization static int for values
     * @throws ioexception
     */
    public flags getholderauthorizationrights()
        throws ioexception
    {
        return new flags(certificatebody.getcertificateholderauthorization().getaccessrights() & 0x1f);
    }
}
