package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.math.biginteger;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.agreement.srp.srp6client;
import org.ripple.bouncycastle.crypto.agreement.srp.srp6util;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.io.signerinputstream;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;
import org.ripple.bouncycastle.util.bigintegers;

/**
 * tls 1.1 srp key exchange (rfc 5054).
 */
public class tlssrpkeyexchange
    extends abstracttlskeyexchange
{

    protected tlssigner tlssigner;
    protected byte[] identity;
    protected byte[] password;

    protected asymmetrickeyparameter serverpublickey = null;

    protected byte[] s = null;
    protected biginteger b = null;
    protected srp6client srpclient = new srp6client();

    public tlssrpkeyexchange(int keyexchange, vector supportedsignaturealgorithms, byte[] identity, byte[] password)
    {

        super(keyexchange, supportedsignaturealgorithms);

        switch (keyexchange)
        {
        case keyexchangealgorithm.srp:
            this.tlssigner = null;
            break;
        case keyexchangealgorithm.srp_rsa:
            this.tlssigner = new tlsrsasigner();
            break;
        case keyexchangealgorithm.srp_dss:
            this.tlssigner = new tlsdsssigner();
            break;
        default:
            throw new illegalargumentexception("unsupported key exchange algorithm");
        }

        this.keyexchange = keyexchange;
        this.identity = identity;
        this.password = password;
    }

    public void init(tlscontext context)
    {
        super.init(context);

        if (this.tlssigner != null)
        {
            this.tlssigner.init(context);
        }
    }

    public void skipservercredentials()
        throws ioexception
    {
        if (tlssigner != null)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
    }

    public void processservercertificate(certificate servercertificate)
        throws ioexception
    {

        if (tlssigner == null)
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

        if (!tlssigner.isvalidpublickey(this.serverpublickey))
        {
            throw new tlsfatalalert(alertdescription.certificate_unknown);
        }

        tlsutils.validatekeyusage(x509cert, keyusage.digitalsignature);

        super.processservercertificate(servercertificate);
    }

    public boolean requiresserverkeyexchange()
    {
        return true;
    }

    public void processserverkeyexchange(inputstream input)
        throws ioexception
    {

        securityparameters securityparameters = context.getsecurityparameters();

        inputstream sigin = input;
        signer signer = null;

        if (tlssigner != null)
        {
            signer = initverifyer(tlssigner, securityparameters);
            sigin = new signerinputstream(input, signer);
        }

        byte[] nbytes = tlsutils.readopaque16(sigin);
        byte[] gbytes = tlsutils.readopaque16(sigin);
        byte[] sbytes = tlsutils.readopaque8(sigin);
        byte[] bbytes = tlsutils.readopaque16(sigin);

        if (signer != null)
        {
            byte[] sigbyte = tlsutils.readopaque16(input);

            if (!signer.verifysignature(sigbyte))
            {
                throw new tlsfatalalert(alertdescription.decrypt_error);
            }
        }

        biginteger n = new biginteger(1, nbytes);
        biginteger g = new biginteger(1, gbytes);

        // todo validate group parameters (see rfc 5054)
        // handler.failwitherror(alertlevel.fatal, alertdescription.insufficient_security);

        this.s = sbytes;

        /*
         * rfc 5054 2.5.3: the client must abort the handshake with an "illegal_parameter" alert if
         * b % n = 0.
         */
        try
        {
            this.b = srp6util.validatepublicvalue(n, new biginteger(1, bbytes));
        }
        catch (cryptoexception e)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        this.srpclient.init(n, g, new sha1digest(), context.getsecurerandom());
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
        byte[] kedata = bigintegers.asunsignedbytearray(srpclient.generateclientcredentials(s, this.identity,
            this.password));
        tlsutils.writeopaque16(kedata, output);
    }

    public byte[] generatepremastersecret()
        throws ioexception
    {
        try
        {
            // todo check if this needs to be a fixed size
            return bigintegers.asunsignedbytearray(srpclient.calculatesecret(b));
        }
        catch (cryptoexception e)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
    }

    protected signer initverifyer(tlssigner tlssigner, securityparameters securityparameters)
    {
        signer signer = tlssigner.createverifyer(this.serverpublickey);
        signer.update(securityparameters.clientrandom, 0, securityparameters.clientrandom.length);
        signer.update(securityparameters.serverrandom, 0, securityparameters.serverrandom.length);
        return signer;
    }
}
