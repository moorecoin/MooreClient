package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.security.securerandom;
import java.util.vector;

import org.ripple.bouncycastle.util.arrays;

public abstract class dtlsprotocol
{

    protected final securerandom securerandom;

    protected dtlsprotocol(securerandom securerandom)
    {

        if (securerandom == null)
        {
            throw new illegalargumentexception("'securerandom' cannot be null");
        }

        this.securerandom = securerandom;
    }

    protected void processfinished(byte[] body, byte[] expected_verify_data)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        byte[] verify_data = tlsutils.readfully(expected_verify_data.length, buf);

        tlsprotocol.assertempty(buf);

        if (!arrays.constanttimeareequal(expected_verify_data, verify_data))
        {
            throw new tlsfatalalert(alertdescription.handshake_failure);
        }
    }

    protected static byte[] generatecertificate(certificate certificate)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        certificate.encode(buf);
        return buf.tobytearray();
    }

    protected static byte[] generatesupplementaldata(vector supplementaldata)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsprotocol.writesupplementaldata(buf, supplementaldata);
        return buf.tobytearray();
    }

    protected static void validateselectedciphersuite(int selectedciphersuite, short alertdescription)
        throws ioexception
    {

        switch (selectedciphersuite)
        {
        case ciphersuite.tls_rsa_export_with_rc4_40_md5:
        case ciphersuite.tls_rsa_with_rc4_128_md5:
        case ciphersuite.tls_rsa_with_rc4_128_sha:
        case ciphersuite.tls_dh_anon_export_with_rc4_40_md5:
        case ciphersuite.tls_dh_anon_with_rc4_128_md5:
        case ciphersuite.tls_psk_with_rc4_128_sha:
        case ciphersuite.tls_dhe_psk_with_rc4_128_sha:
        case ciphersuite.tls_rsa_psk_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_rsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdhe_rsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_anon_with_rc4_128_sha:
            // todo alert
            throw new illegalstateexception("rc4 must not be used with dtls");
        }
    }
}
