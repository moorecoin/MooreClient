package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;
import org.ripple.bouncycastle.util.io.streams;

/**
 * tls 1.0/1.1 and sslv3 rsa key exchange.
 */
public class tlsrsakeyexchange
    extends abstracttlskeyexchange
{
    protected asymmetrickeyparameter serverpublickey = null;

    protected rsakeyparameters rsaserverpublickey = null;

    protected tlsencryptioncredentials servercredentials = null;

    protected byte[] premastersecret;

    public tlsrsakeyexchange(vector supportedsignaturealgorithms)
    {
        super(keyexchangealgorithm.rsa, supportedsignaturealgorithms);
    }

    public void skipservercredentials()
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.unexpected_message);
    }

    public void processservercredentials(tlscredentials servercredentials)
        throws ioexception
    {

        if (!(servercredentials instanceof tlsencryptioncredentials))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        processservercertificate(servercredentials.getcertificate());

        this.servercredentials = (tlsencryptioncredentials)servercredentials;
    }

    public void processservercertificate(certificate servercertificate)
        throws ioexception
    {

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

    public void validatecertificaterequest(certificaterequest certificaterequest)
        throws ioexception
    {
        short[] types = certificaterequest.getcertificatetypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case clientcertificatetype.rsa_sign:
            case clientcertificatetype.dss_sign:
            case clientcertificatetype.ecdsa_sign:
                break;
            default:
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
    }

    public void processclientcredentials(tlscredentials clientcredentials)
        throws ioexception
    {
        if (!(clientcredentials instanceof tlssignercredentials))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public void generateclientkeyexchange(outputstream output)
        throws ioexception
    {
        this.premastersecret = tlsrsautils.generateencryptedpremastersecret(context, this.rsaserverpublickey, output);
    }

    public void processclientkeyexchange(inputstream input)
        throws ioexception
    {

        byte[] encryptedpremastersecret;
        if (context.getserverversion().isssl())
        {
            // todo do any sslv3 clients actually include the length?
            encryptedpremastersecret = streams.readall(input);
        }
        else
        {
            encryptedpremastersecret = tlsutils.readopaque16(input);
        }

        protocolversion clientversion = context.getclientversion();

        /*
         * rfc 5246 7.4.7.1.
         */
        {
            // todo provide as configuration option?
            boolean versionnumbercheckdisabled = false;

            /*
             * see notes regarding bleichenbacher/klima attack. the code here implements the first
             * construction proposed there, which is recommended.
             */
            byte[] r = new byte[48];
            this.context.getsecurerandom().nextbytes(r);

            byte[] m = tlsutils.empty_bytes;
            try
            {
                m = servercredentials.decryptpremastersecret(encryptedpremastersecret);
            }
            catch (exception e)
            {
                /*
                 * in any case, a tls server must not generate an alert if processing an
                 * rsa-encrypted premaster secret message fails, or the version number is not as
                 * expected. instead, it must continue the handshake with a randomly generated
                 * premaster secret.
                 */
            }

            if (m.length != 48)
            {
                tlsutils.writeversion(clientversion, r, 0);
                this.premastersecret = r;
            }
            else
            {
                /*
                 * if clienthello.client_version is tls 1.1 or higher, server implementations must
                 * check the version number [..].
                 */
                if (versionnumbercheckdisabled && clientversion.isequalorearlierversionof(protocolversion.tlsv10))
                {
                    /*
                     * if the version number is tls 1.0 or earlier, server implementations should
                     * check the version number, but may have a configuration option to disable the
                     * check.
                     */
                }
                else
                {
                    /*
                     * note that explicitly constructing the pre_master_secret with the
                     * clienthello.client_version produces an invalid master_secret if the client
                     * has sent the wrong version in the original pre_master_secret.
                     */
                    tlsutils.writeversion(clientversion, m, 0);
                }
                this.premastersecret = m;
            }
        }
    }

    public byte[] generatepremastersecret()
        throws ioexception
    {
        if (this.premastersecret == null)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        byte[] tmp = this.premastersecret;
        this.premastersecret = null;
        return tmp;
    }

    // would be needed to process rsa_export server key exchange
    // protected void processrsaserverkeyexchange(inputstream is, signer signer) throws ioexception
    // {
    // inputstream sigin = is;
    // if (signer != null)
    // {
    // sigin = new signerinputstream(is, signer);
    // }
    //
    // byte[] modulusbytes = tlsutils.readopaque16(sigin);
    // byte[] exponentbytes = tlsutils.readopaque16(sigin);
    //
    // if (signer != null)
    // {
    // byte[] sigbyte = tlsutils.readopaque16(is);
    //
    // if (!signer.verifysignature(sigbyte))
    // {
    // handler.failwitherror(alertlevel.fatal, alertdescription.bad_certificate);
    // }
    // }
    //
    // biginteger modulus = new biginteger(1, modulusbytes);
    // biginteger exponent = new biginteger(1, exponentbytes);
    //
    // this.rsaserverpublickey = validatersapublickey(new rsakeyparameters(false, modulus,
    // exponent));
    // }

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
