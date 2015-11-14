package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

/**
 * a generic interface for key exchange implementations in tls 1.0/1.1.
 */
public interface tlskeyexchange
{

    void init(tlscontext context);

    void skipservercredentials()
        throws ioexception;

    void processservercredentials(tlscredentials servercredentials)
        throws ioexception;

    void processservercertificate(certificate servercertificate)
        throws ioexception;

    boolean requiresserverkeyexchange();

    byte[] generateserverkeyexchange()
        throws ioexception;

    void skipserverkeyexchange()
        throws ioexception;

    void processserverkeyexchange(inputstream input)
        throws ioexception;

    void validatecertificaterequest(certificaterequest certificaterequest)
        throws ioexception;

    void skipclientcredentials()
        throws ioexception;

    void processclientcredentials(tlscredentials clientcredentials)
        throws ioexception;

    void processclientcertificate(certificate clientcertificate)
        throws ioexception;

    void generateclientkeyexchange(outputstream output)
        throws ioexception;

    void processclientkeyexchange(inputstream input)
        throws ioexception;

    byte[] generatepremastersecret()
        throws ioexception;
}
