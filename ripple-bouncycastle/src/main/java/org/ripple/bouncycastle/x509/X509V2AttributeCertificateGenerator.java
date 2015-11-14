package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.generalsecurityexception;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.securerandom;
import java.security.signatureexception;
import java.security.cert.certificateencodingexception;
import java.util.date;
import java.util.iterator;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.attcertissuer;
import org.ripple.bouncycastle.asn1.x509.attribute;
import org.ripple.bouncycastle.asn1.x509.attributecertificate;
import org.ripple.bouncycastle.asn1.x509.attributecertificateinfo;
import org.ripple.bouncycastle.asn1.x509.v2attributecertificateinfogenerator;
import org.ripple.bouncycastle.asn1.x509.x509extensionsgenerator;

/**
 * class to produce an x.509 version 2 attributecertificate.
 * @deprecated use org.bouncycastle.cert.x509v2attributecertificatebuilder
 */
public class x509v2attributecertificategenerator
{
    private v2attributecertificateinfogenerator   acinfogen;
    private derobjectidentifier         sigoid;
    private algorithmidentifier         sigalgid;
    private string                      signaturealgorithm;
    private x509extensionsgenerator     extgenerator;

    public x509v2attributecertificategenerator()
    {
        acinfogen = new v2attributecertificateinfogenerator();
        extgenerator = new x509extensionsgenerator();
    }

    /**
     * reset the generator
     */
    public void reset()
    {
        acinfogen = new v2attributecertificateinfogenerator();
        extgenerator.reset();
    }

    /**
     * set the holder of this attribute certificate
     */
    public void setholder(
        attributecertificateholder     holder)
    {
        acinfogen.setholder(holder.holder);
    }

    /**
     * set the issuer
     */
    public void setissuer(
        attributecertificateissuer  issuer)
    {
        acinfogen.setissuer(attcertissuer.getinstance(issuer.form));
    }

    /**
     * set the serial number for the certificate.
     */
    public void setserialnumber(
        biginteger      serialnumber)
    {
        acinfogen.setserialnumber(new asn1integer(serialnumber));
    }

    public void setnotbefore(
        date    date)
    {
        acinfogen.setstartdate(new asn1generalizedtime(date));
    }

    public void setnotafter(
        date    date)
    {
        acinfogen.setenddate(new asn1generalizedtime(date));
    }

    /**
     * set the signature algorithm. this can be either a name or an oid, names
     * are treated as case insensitive.
     * 
     * @param signaturealgorithm string representation of the algorithm name.
     */
    public void setsignaturealgorithm(
        string  signaturealgorithm)
    {
        this.signaturealgorithm = signaturealgorithm;

        try
        {
            sigoid = x509util.getalgorithmoid(signaturealgorithm);
        }
        catch (exception e)
        {
            throw new illegalargumentexception("unknown signature type requested");
        }

        sigalgid = x509util.getsigalgid(sigoid, signaturealgorithm);

        acinfogen.setsignature(sigalgid);
    }
    
    /**
     * add an attribute
     */
    public void addattribute(
        x509attribute       attribute)
    {
        acinfogen.addattribute(attribute.getinstance(attribute.toasn1object()));
    }

    public void setissueruniqueid(
        boolean[] iui)
    {
        // [todo] convert boolean array to bit string
        //acinfogen.setissueruniqueid(iui);
        throw new runtimeexception("not implemented (yet)");
    }
     
    /**
     * add a given extension field for the standard extensions tag
     * @throws ioexception
     */
    public void addextension(
        string          oid,
        boolean         critical,
        asn1encodable   value)
        throws ioexception
    {
        extgenerator.addextension(new asn1objectidentifier(oid), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag
     * the value parameter becomes the contents of the octet string associated
     * with the extension.
     */
    public void addextension(
        string          oid,
        boolean         critical,
        byte[]          value)
    {
        extgenerator.addextension(new asn1objectidentifier(oid), critical, value);
    }

    /**
     * generate an x509 certificate, based on the current issuer and subject,
     * using the passed in provider for the signing.
     * @deprecated use generate()
     */
    public x509attributecertificate generatecertificate(
        privatekey      key,
        string          provider)
        throws nosuchproviderexception, securityexception, signatureexception, invalidkeyexception
    {
        return generatecertificate(key, provider, null);
    }

    /**
     * generate an x509 certificate, based on the current issuer and subject,
     * using the passed in provider for the signing and the supplied source
     * of randomness, if required.
     * @deprecated use generate()
     */
    public x509attributecertificate generatecertificate(
        privatekey      key,
        string          provider,
        securerandom    random)
        throws nosuchproviderexception, securityexception, signatureexception, invalidkeyexception
    {
        try
        {
            return generate(key, provider, random);
        }
        catch (nosuchproviderexception e)
        {
            throw e;
        }
        catch (signatureexception e)
        {
            throw e;
        }
        catch (invalidkeyexception e)
        {
            throw e;
        }
        catch (generalsecurityexception e)
        {
            throw new securityexception("exception creating certificate: " + e);
        }
    }

   /**
     * generate an x509 certificate, based on the current issuer and subject,
     * using the passed in provider for the signing.
     */
    public x509attributecertificate generate(
        privatekey      key,
        string          provider)
       throws certificateencodingexception, illegalstateexception, nosuchproviderexception, signatureexception, invalidkeyexception, nosuchalgorithmexception
   {
        return generate(key, provider, null);
    }

    /**
     * generate an x509 certificate, based on the current issuer and subject,
     * using the passed in provider for the signing and the supplied source
     * of randomness, if required.
     */
    public x509attributecertificate generate(
        privatekey      key,
        string          provider,
        securerandom    random)
        throws certificateencodingexception, illegalstateexception, nosuchproviderexception, nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        if (!extgenerator.isempty())
        {
            acinfogen.setextensions(extgenerator.generate());
        }

        attributecertificateinfo acinfo = acinfogen.generateattributecertificateinfo();

        asn1encodablevector  v = new asn1encodablevector();

        v.add(acinfo);
        v.add(sigalgid);

        try
        {
            v.add(new derbitstring(x509util.calculatesignature(sigoid, signaturealgorithm, provider, key, random, acinfo)));

            return new x509v2attributecertificate(new attributecertificate(new dersequence(v)));
        }
        catch (ioexception e)
        {
            throw new extcertificateencodingexception("constructed invalid certificate", e);
        }
    }

    /**
     * return an iterator of the signature names supported by the generator.
     * 
     * @return an iterator containing recognised names.
     */
    public iterator getsignaturealgnames()
    {
        return x509util.getalgnames();
    }
}
