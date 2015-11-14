package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.math.biginteger;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;

/**
 * tls 1.0 psk key exchange (rfc 4279).
 */
public class tlspskkeyexchange
    extends abstracttlskeyexchange
{

    protected tlspskidentity pskidentity;

    protected byte[] psk_identity_hint = null;

    protected dhpublickeyparameters dhagreeserverpublickey = null;
    protected dhprivatekeyparameters dhagreeclientprivatekey = null;

    protected asymmetrickeyparameter serverpublickey = null;
    protected rsakeyparameters rsaserverpublickey = null;
    protected byte[] premastersecret;

    public tlspskkeyexchange(int keyexchange, vector supportedsignaturealgorithms, tlspskidentity pskidentity)
    {
        super(keyexchange, supportedsignaturealgorithms);

        switch (keyexchange)
        {
        case keyexchangealgorithm.psk:
        case keyexchangealgorithm.rsa_psk:
        case keyexchangealgorithm.dhe_psk:
            break;
        default:
            throw new illegalargumentexception("unsupported key exchange algorithm");
        }

        this.pskidentity = pskidentity;
    }

    public void skipservercredentials()
        throws ioexception
    {
        if (keyexchange == keyexchangealgorithm.rsa_psk)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
    }

    public void processservercertificate(certificate servercertificate)
        throws ioexception
    {

        if (keyexchange != keyexchangealgorithm.rsa_psk)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
        if (servercertificate.isempty())
        {
            throw new tlsfatalalert(alertdescription.bad_certificate);
        }

        org.ripple.bouncycastle.asn1.x509.certificate x509cert = servercertificate.getcertificateat(0);

        subjectpublickeyinfo keyinfo = x509cert.getsubjectpublickeyinfo();
        try
        {
            this.serverpublickey = publickeyfactory.createkey(keyinfo);
        }
        catch (runtimeexception e)
        {
            throw new tlsfatalalert(alertdescription.unsupported_certificate);
        }

        // sanity check the publickeyfactory
        if (this.serverpublickey.isprivate())
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        this.rsaserverpublickey = validatersapublickey((rsakeyparameters)this.serverpublickey);

        tlsutils.validatekeyusage(x509cert, keyusage.keyencipherment);

        super.processservercertificate(servercertificate);
    }

    public boolean requiresserverkeyexchange()
    {
        return keyexchange == keyexchangealgorithm.dhe_psk;
    }

    public void processserverkeyexchange(inputstream input)
        throws ioexception
    {

        this.psk_identity_hint = tlsutils.readopaque16(input);

        if (this.keyexchange == keyexchangealgorithm.dhe_psk)
        {
            byte[] pbytes = tlsutils.readopaque16(input);
            byte[] gbytes = tlsutils.readopaque16(input);
            byte[] ysbytes = tlsutils.readopaque16(input);

            biginteger p = new biginteger(1, pbytes);
            biginteger g = new biginteger(1, gbytes);
            biginteger ys = new biginteger(1, ysbytes);

            this.dhagreeserverpublickey = tlsdhutils.validatedhpublickey(new dhpublickeyparameters(ys,
                new dhparameters(p, g)));
        }
    }

    public void validatecertificaterequest(certificaterequest certificaterequest)
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.unexpected_message);
    }

    public void processclientcredentials(tlscredentials clientcredentials)
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.internal_error);
    }

    public void generateclientkeyexchange(outputstream output)
        throws ioexception
    {

        if (psk_identity_hint == null)
        {
            pskidentity.skipidentityhint();
        }
        else
        {
            pskidentity.notifyidentityhint(psk_identity_hint);
        }

        byte[] psk_identity = pskidentity.getpskidentity();

        tlsutils.writeopaque16(psk_identity, output);

        if (this.keyexchange == keyexchangealgorithm.rsa_psk)
        {
            this.premastersecret = tlsrsautils.generateencryptedpremastersecret(context, this.rsaserverpublickey,
                output);
        }
        else if (this.keyexchange == keyexchangealgorithm.dhe_psk)
        {
            this.dhagreeclientprivatekey = tlsdhutils.generateephemeralclientkeyexchange(context.getsecurerandom(),
                dhagreeserverpublickey.getparameters(), output);
        }
    }

    public byte[] generatepremastersecret()
        throws ioexception
    {

        byte[] psk = pskidentity.getpsk();
        byte[] other_secret = generateothersecret(psk.length);

        bytearrayoutputstream buf = new bytearrayoutputstream(4 + other_secret.length + psk.length);
        tlsutils.writeopaque16(other_secret, buf);
        tlsutils.writeopaque16(psk, buf);
        return buf.tobytearray();
    }

    protected byte[] generateothersecret(int psklength)
    {

        if (this.keyexchange == keyexchangealgorithm.dhe_psk)
        {
            return tlsdhutils.calculatedhbasicagreement(dhagreeserverpublickey, dhagreeclientprivatekey);
        }

        if (this.keyexchange == keyexchangealgorithm.rsa_psk)
        {
            return this.premastersecret;
        }

        return new byte[psklength];
    }

    protected rsakeyparameters validatersapublickey(rsakeyparameters key)
        throws ioexception
    {
        // todo what is the minimum bit length required?
        // key.getmodulus().bitlength();

        if (!key.getexponent().isprobableprime(2))
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        return key;
    }
}
