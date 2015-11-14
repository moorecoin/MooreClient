package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.util.vector;

public abstract class abstracttlskeyexchange
    implements tlskeyexchange
{

    protected int keyexchange;
    protected vector supportedsignaturealgorithms;

    protected tlscontext context;

    protected abstracttlskeyexchange(int keyexchange, vector supportedsignaturealgorithms)
    {
        this.keyexchange = keyexchange;
        this.supportedsignaturealgorithms = supportedsignaturealgorithms;
    }

    public void init(tlscontext context)
    {
        this.context = context;

        protocolversion clientversion = context.getclientversion();

        if (tlsutils.issignaturealgorithmsextensionallowed(clientversion))
        {

            /*
             * rfc 5264 7.4.1.4.1. if the client does not send the signature_algorithms extension,
             * the server must do the following:
             * 
             * - if the negotiated key exchange algorithm is one of (rsa, dhe_rsa, dh_rsa, rsa_psk,
             * ecdh_rsa, ecdhe_rsa), behave as if client had sent the value {sha1,rsa}.
             * 
             * - if the negotiated key exchange algorithm is one of (dhe_dss, dh_dss), behave as if
             * the client had sent the value {sha1,dsa}.
             * 
             * - if the negotiated key exchange algorithm is one of (ecdh_ecdsa, ecdhe_ecdsa),
             * behave as if the client had sent value {sha1,ecdsa}.
             */
            if (this.supportedsignaturealgorithms == null)
            {
                switch (keyexchange)
                {

                case keyexchangealgorithm.dh_dss:
                case keyexchangealgorithm.dhe_dss:
                case keyexchangealgorithm.srp_dss:
                {
                    this.supportedsignaturealgorithms = tlsutils.getdefaultdsssignaturealgorithms();
                    break;
                }

                case keyexchangealgorithm.ecdh_ecdsa:
                case keyexchangealgorithm.ecdhe_ecdsa:
                {
                    this.supportedsignaturealgorithms = tlsutils.getdefaultecdsasignaturealgorithms();
                    break;
                }

                case keyexchangealgorithm.dh_rsa:
                case keyexchangealgorithm.dhe_rsa:
                case keyexchangealgorithm.ecdh_rsa:
                case keyexchangealgorithm.ecdhe_rsa:
                case keyexchangealgorithm.rsa:
                case keyexchangealgorithm.rsa_psk:
                case keyexchangealgorithm.srp_rsa:
                {
                    this.supportedsignaturealgorithms = tlsutils.getdefaultrsasignaturealgorithms();
                    break;
                }

                default:
                    throw new illegalstateexception("unsupported key exchange algorithm");
                }
            }

        }
        else if (this.supportedsignaturealgorithms != null)
        {
            throw new illegalstateexception("supported_signature_algorithms not allowed for " + clientversion);
        }
    }

    public void processservercertificate(certificate servercertificate)
        throws ioexception
    {

        if (supportedsignaturealgorithms == null)
        {
            /*
             * todo rfc 2264 7.4.2. unless otherwise specified, the signing algorithm for the
             * certificate must be the same as the algorithm for the certificate key.
             */
        }
        else
        {
            /*
             * todo rfc 5264 7.4.2. if the client provided a "signature_algorithms" extension, then
             * all certificates provided by the server must be signed by a hash/signature algorithm
             * pair that appears in that extension.
             */
        }
    }

    public void processservercredentials(tlscredentials servercredentials)
        throws ioexception
    {
        processservercertificate(servercredentials.getcertificate());
    }

    public boolean requiresserverkeyexchange()
    {
        return false;
    }

    public byte[] generateserverkeyexchange()
        throws ioexception
    {
        if (requiresserverkeyexchange())
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }
        return null;
    }

    public void skipserverkeyexchange()
        throws ioexception
    {
        if (requiresserverkeyexchange())
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
    }

    public void processserverkeyexchange(inputstream input)
        throws ioexception
    {
        if (!requiresserverkeyexchange())
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
    }

    public void skipclientcredentials()
        throws ioexception
    {
    }

    public void processclientcertificate(certificate clientcertificate)
        throws ioexception
    {
    }

    public void processclientkeyexchange(inputstream input)
        throws ioexception
    {
        // key exchange implementation must support client key exchange
        throw new tlsfatalalert(alertdescription.internal_error);
    }
}
