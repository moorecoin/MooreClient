package org.ripple.bouncycastle.asn1.eac;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.bertags;
import org.ripple.bouncycastle.asn1.derapplicationspecific;
import org.ripple.bouncycastle.asn1.deroctetstring;


/**
 * an iso7816certificatebody structure.
 * <p/>
 * <pre>
 *  certificatebody ::= sequence {
 *      // version of the certificate format. must be 0 (version 1)
 *      certificateprofileidentifer         derapplicationspecific,
 *      //uniquely identifies the issuinng ca's signature key pair
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of issuer and the sequence number of the key pair.
 *      certificationauthorityreference        derapplicationspecific,
 *      // stores the encoded public key
 *      publickey                            iso7816publickey,
 *      //associates the public key contained in the certificate with a unique name
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of the holder and the sequence number of the key pair.
 *      certificateholderreference            derapplicationspecific,
 *      // encodes the role of the holder (i.e. cvca, dv, is) and assigns read/write
 *      // access rights to data groups storing sensitive data
 *      certificateholderauthorization        iso7816certificateholderauthorization,
 *      // the date of the certificate generation
 *      certificateeffectivedate            derapplicationspecific,
 *      // the date after wich the certificate expires
 *      certificateexpirationdate            derapplicationspecific
 *  }
 * </pre>
 */
public class certificatebody
    extends asn1object
{
    asn1inputstream seq;
    private derapplicationspecific certificateprofileidentifier;// version of the certificate format. must be 0 (version 1)
    private derapplicationspecific certificationauthorityreference;//uniquely identifies the issuinng ca's signature key pair
    private publickeydataobject publickey;// stores the encoded public key
    private derapplicationspecific certificateholderreference;//associates the public key contained in the certificate with a unique name
    private certificateholderauthorization certificateholderauthorization;// encodes the role of the holder (i.e. cvca, dv, is) and assigns read/write access rights to data groups storing sensitive data
    private derapplicationspecific certificateeffectivedate;// the date of the certificate generation
    private derapplicationspecific certificateexpirationdate;// the date after wich the certificate expires
    private int certificatetype = 0;// bit field of initialized data. this will tell us if the data are valid.
    private static final int cpi = 0x01;//certificate profile identifier
    private static final int car = 0x02;//certification authority reference
    private static final int pk = 0x04;//public key
    private static final int chr = 0x08;//certificate holder reference
    private static final int cha = 0x10;//certificate holder authorization
    private static final int cefd = 0x20;//certificate effective date
    private static final int cexd = 0x40;//certificate expiration date

    public static final int profiletype = 0x7f;//profile type certificate
    public static final int requesttype = 0x0d;// request type certificate

    private void setiso7816certificatebody(derapplicationspecific appspe)
        throws ioexception
    {
        byte[] content;
        if (appspe.getapplicationtag() == eactags.certificate_content_template)
        {
            content = appspe.getcontents();
        }
        else
        {
            throw new ioexception("bad tag : not an iso7816 certificate_content_template");
        }
        asn1inputstream ais = new asn1inputstream(content);
        asn1primitive obj;
        while ((obj = ais.readobject()) != null)
        {
            derapplicationspecific aspe;

            if (obj instanceof derapplicationspecific)
            {
                aspe = (derapplicationspecific)obj;
            }
            else
            {
                throw new ioexception("not a valid iso7816 content : not a derapplicationspecific object :" + eactags.encodetag(appspe) + obj.getclass());
            }
            switch (aspe.getapplicationtag())
            {
            case eactags.interchange_profile:
                setcertificateprofileidentifier(aspe);
                break;
            case eactags.issuer_identification_number:
                setcertificationauthorityreference(aspe);
                break;
            case eactags.cardholder_public_key_template:
                setpublickey(publickeydataobject.getinstance(aspe.getobject(bertags.sequence)));
                break;
            case eactags.cardholder_name:
                setcertificateholderreference(aspe);
                break;
            case eactags.certificate_holder_authorization_template:
                setcertificateholderauthorization(new certificateholderauthorization(aspe));
                break;
            case eactags.application_effective_date:
                setcertificateeffectivedate(aspe);
                break;
            case eactags.application_expiration_date:
                setcertificateexpirationdate(aspe);
                break;
            default:
                certificatetype = 0;
                throw new ioexception("not a valid iso7816 derapplicationspecific tag " + aspe.getapplicationtag());
            }
        }
    }

    /**
     * builds an iso7816certificatebody by settings each parameters.
     *
     * @param certificateprofileidentifier
     * @param certificationauthorityreference
     *
     * @param publickey
     * @param certificateholderreference
     * @param certificateholderauthorization
     * @param certificateeffectivedate
     * @param certificateexpirationdate
     * @throws ioexception
     */
    public certificatebody(
        derapplicationspecific certificateprofileidentifier,
        certificationauthorityreference certificationauthorityreference,
        publickeydataobject publickey,
        certificateholderreference certificateholderreference,
        certificateholderauthorization certificateholderauthorization,
        packeddate certificateeffectivedate,
        packeddate certificateexpirationdate
    )
    {
        setcertificateprofileidentifier(certificateprofileidentifier);
        setcertificationauthorityreference(new derapplicationspecific(
            eactags.issuer_identification_number, certificationauthorityreference.getencoded()));
        setpublickey(publickey);
        setcertificateholderreference(new derapplicationspecific(
            eactags.cardholder_name, certificateholderreference.getencoded()));
        setcertificateholderauthorization(certificateholderauthorization);
        try
        {
            setcertificateeffectivedate(new derapplicationspecific(
                false, eactags.application_effective_date, new deroctetstring(certificateeffectivedate.getencoding())));
            setcertificateexpirationdate(new derapplicationspecific(
                false, eactags.application_expiration_date, new deroctetstring(certificateexpirationdate.getencoding())));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("unable to encode dates: " + e.getmessage());
        }
    }

    /**
     * builds an iso7816certificatebody with an asn1inputstream.
     *
     * @param obj derapplicationspecific containing the whole body.
     * @throws ioexception if the body is not valid.
     */
    private certificatebody(derapplicationspecific obj)
        throws ioexception
    {
        setiso7816certificatebody(obj);
    }

    /**
     * create a profile type iso7816certificatebody.
     *
     * @return return the "profile" type certificate body.
     * @throws ioexception if the derapplicationspecific cannot be created.
     */
    private asn1primitive profiletoasn1object()
        throws ioexception
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certificateprofileidentifier);
        v.add(certificationauthorityreference);
        v.add(new derapplicationspecific(false, eactags.cardholder_public_key_template, publickey));
        v.add(certificateholderreference);
        v.add(certificateholderauthorization);
        v.add(certificateeffectivedate);
        v.add(certificateexpirationdate);
        return new derapplicationspecific(eactags.certificate_content_template, v);
    }

    private void setcertificateprofileidentifier(derapplicationspecific certificateprofileidentifier)
        throws illegalargumentexception
    {
        if (certificateprofileidentifier.getapplicationtag() == eactags.interchange_profile)
        {
            this.certificateprofileidentifier = certificateprofileidentifier;
            certificatetype |= cpi;
        }
        else
        {
            throw new illegalargumentexception("not an iso7816tags.interchange_profile tag :" + eactags.encodetag(certificateprofileidentifier));
        }
    }

    private void setcertificateholderreference(derapplicationspecific certificateholderreference)
        throws illegalargumentexception
    {
        if (certificateholderreference.getapplicationtag() == eactags.cardholder_name)
        {
            this.certificateholderreference = certificateholderreference;
            certificatetype |= chr;
        }
        else
        {
            throw new illegalargumentexception("not an iso7816tags.cardholder_name tag");
        }
    }

    /**
     * set the certificationauthorityreference.
     *
     * @param certificationauthorityreference
     *         the derapplicationspecific containing the certificationauthorityreference.
     * @throws illegalargumentexception if the derapplicationspecific is not valid.
     */
    private void setcertificationauthorityreference(
        derapplicationspecific certificationauthorityreference)
        throws illegalargumentexception
    {
        if (certificationauthorityreference.getapplicationtag() == eactags.issuer_identification_number)
        {
            this.certificationauthorityreference = certificationauthorityreference;
            certificatetype |= car;
        }
        else
        {
            throw new illegalargumentexception("not an iso7816tags.issuer_identification_number tag");
        }
    }

    /**
     * set the public key
     *
     * @param publickey : the derapplicationspecific containing the public key
     * @throws java.io.ioexception
     */
    private void setpublickey(publickeydataobject publickey)
    {
        this.publickey = publickeydataobject.getinstance(publickey);
        this.certificatetype |= pk;
    }

    /**
     * create a request type iso7816certificatebody.
     *
     * @return return the "request" type certificate body.
     * @throws ioexception if the derapplicationspecific cannot be created.
     */
    private asn1primitive requesttoasn1object()
        throws ioexception
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certificateprofileidentifier);
        v.add(new derapplicationspecific(false, eactags.cardholder_public_key_template, publickey));
        v.add(certificateholderreference);
        return new derapplicationspecific(eactags.certificate_content_template, v);
    }

    /**
     * create a "request" or "profile" type iso7816certificatebody according to the variables sets.
     *
     * @return return the asn1primitive representing the "request" or "profile" type certificate body.
     * @throws ioexception if the derapplicationspecific cannot be created or if data are missings to create a valid certificate.
     */
    public asn1primitive toasn1primitive()
    {
        try
        {
            if (certificatetype == profiletype)
            {
                return profiletoasn1object();
            }
            if (certificatetype == requesttype)
            {
                return requesttoasn1object();
            }
        }
        catch (ioexception e)
        {
            return null;
        }
        return null;
    }

    /**
     * gives the type of the certificate (value should be profiletype or requesttype if all data are set).
     *
     * @return the int representing the data already set.
     */
    public int getcertificatetype()
    {
        return certificatetype;
    }

    /**
     * gives an instance of iso7816certificatebody taken from object obj
     *
     * @param obj is the object to extract the certificate body from.
     * @return the iso7816certificatebody taken from object obj.
     * @throws ioexception if object is not valid.
     */
    public static certificatebody getinstance(object obj)
        throws ioexception
    {
        if (obj instanceof certificatebody)
        {
            return (certificatebody)obj;
        }
        else if (obj != null)
        {
            return new certificatebody(derapplicationspecific.getinstance(obj));
        }

        return null;
    }

    /**
     * @return the date of the certificate generation
     */
    public packeddate getcertificateeffectivedate()
    {
        if ((this.certificatetype & certificatebody.cefd) ==
            certificatebody.cefd)
        {
            return new packeddate(certificateeffectivedate.getcontents());
        }
        return null;
    }

    /**
     * set the date of the certificate generation
     *
     * @param ced derapplicationspecific containing the date of the certificate generation
     * @throws illegalargumentexception if the tag is not iso7816tags.application_effective_date
     */
    private void setcertificateeffectivedate(derapplicationspecific ced)
        throws illegalargumentexception
    {
        if (ced.getapplicationtag() == eactags.application_effective_date)
        {
            this.certificateeffectivedate = ced;
            certificatetype |= cefd;
        }
        else
        {
            throw new illegalargumentexception("not an iso7816tags.application_effective_date tag :" + eactags.encodetag(ced));
        }
    }

    /**
     * @return the date after wich the certificate expires
     */
    public packeddate getcertificateexpirationdate()
        throws ioexception
    {
        if ((this.certificatetype & certificatebody.cexd) ==
            certificatebody.cexd)
        {
            return new packeddate(certificateexpirationdate.getcontents());
        }
        throw new ioexception("certificate expiration date not set");
    }

    /**
     * set the date after wich the certificate expires
     *
     * @param ced derapplicationspecific containing the date after wich the certificate expires
     * @throws illegalargumentexception if the tag is not iso7816tags.application_expiration_date
     */
    private void setcertificateexpirationdate(derapplicationspecific ced)
        throws illegalargumentexception
    {
        if (ced.getapplicationtag() == eactags.application_expiration_date)
        {
            this.certificateexpirationdate = ced;
            certificatetype |= cexd;
        }
        else
        {
            throw new illegalargumentexception("not an iso7816tags.application_expiration_date tag");
        }
    }

    /**
     * the iso7816certificateholderauthorization encodes the role of the holder
     * (i.e. cvca, dv, is) and assigns read/write access rights to data groups
     * storing sensitive data. this functions returns the certificate holder
     * authorization
     *
     * @return the iso7816certificateholderauthorization
     */
    public certificateholderauthorization getcertificateholderauthorization()
        throws ioexception
    {
        if ((this.certificatetype & certificatebody.cha) ==
            certificatebody.cha)
        {
            return certificateholderauthorization;
        }
        throw new ioexception("certificate holder authorisation not set");
    }

    /**
     * set the certificateholderauthorization
     *
     * @param cha the certificate holder authorization
     */
    private void setcertificateholderauthorization(
        certificateholderauthorization cha)
    {
        this.certificateholderauthorization = cha;
        certificatetype |= cha;
    }

    /**
     * certificateholderreference : associates the public key contained in the certificate with a unique name
     *
     * @return the certificateholderreference.
     */
    public certificateholderreference getcertificateholderreference()
    {
        return new certificateholderreference(certificateholderreference.getcontents());
    }

    /**
     * certificateprofileidentifier : version of the certificate format. must be 0 (version 1)
     *
     * @return the certificateprofileidentifier
     */
    public derapplicationspecific getcertificateprofileidentifier()
    {
        return certificateprofileidentifier;
    }

    /**
     * get the certificationauthorityreference
     * certificationauthorityreference : uniquely identifies the issuinng ca's signature key pair
     *
     * @return the certificationauthorityreference
     */
    public certificationauthorityreference getcertificationauthorityreference()
        throws ioexception
    {
        if ((this.certificatetype & certificatebody.car) ==
            certificatebody.car)
        {
            return new certificationauthorityreference(certificationauthorityreference.getcontents());
        }
        throw new ioexception("certification authority reference not set");
    }

    /**
     * @return the publickey
     */
    public publickeydataobject getpublickey()
    {
        return publickey;
    }
}
