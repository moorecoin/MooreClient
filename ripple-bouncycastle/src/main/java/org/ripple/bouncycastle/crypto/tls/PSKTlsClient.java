package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public abstract class psktlsclient
    extends abstracttlsclient
{
    protected tlspskidentity pskidentity;

    public psktlsclient(tlspskidentity pskidentity)
    {
        super();
        this.pskidentity = pskidentity;
    }

    public psktlsclient(tlscipherfactory cipherfactory, tlspskidentity pskidentity)
    {
        super(cipherfactory);
        this.pskidentity = pskidentity;
    }

    public int[] getciphersuites()
    {
        return new int[]{ciphersuite.tls_dhe_psk_with_aes_256_cbc_sha, ciphersuite.tls_dhe_psk_with_aes_128_cbc_sha,
            ciphersuite.tls_dhe_psk_with_3des_ede_cbc_sha, ciphersuite.tls_dhe_psk_with_rc4_128_sha,
            ciphersuite.tls_rsa_psk_with_aes_256_cbc_sha, ciphersuite.tls_rsa_psk_with_aes_128_cbc_sha,
            ciphersuite.tls_rsa_psk_with_3des_ede_cbc_sha, ciphersuite.tls_rsa_psk_with_rc4_128_sha,
            ciphersuite.tls_psk_with_aes_256_cbc_sha, ciphersuite.tls_psk_with_aes_128_cbc_sha,
            ciphersuite.tls_psk_with_3des_ede_cbc_sha, ciphersuite.tls_psk_with_rc4_128_sha,};
    }

    public tlskeyexchange getkeyexchange()
        throws ioexception
    {

        switch (selectedciphersuite)
        {
        case ciphersuite.tls_psk_with_3des_ede_cbc_sha:
        case ciphersuite.tls_psk_with_aes_128_cbc_sha:
        case ciphersuite.tls_psk_with_aes_256_cbc_sha:
        case ciphersuite.tls_psk_with_null_sha:
        case ciphersuite.tls_psk_with_rc4_128_sha:
            return createpskkeyexchange(keyexchangealgorithm.psk);

        case ciphersuite.tls_rsa_psk_with_3des_ede_cbc_sha:
        case ciphersuite.tls_rsa_psk_with_aes_128_cbc_sha:
        case ciphersuite.tls_rsa_psk_with_aes_256_cbc_sha:
        case ciphersuite.tls_rsa_psk_with_null_sha:
        case ciphersuite.tls_rsa_psk_with_rc4_128_sha:
            return createpskkeyexchange(keyexchangealgorithm.rsa_psk);

        case ciphersuite.tls_dhe_psk_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dhe_psk_with_aes_128_cbc_sha:
        case ciphersuite.tls_dhe_psk_with_aes_256_cbc_sha:
        case ciphersuite.tls_dhe_psk_with_null_sha:
        case ciphersuite.tls_dhe_psk_with_rc4_128_sha:
            return createpskkeyexchange(keyexchangealgorithm.dhe_psk);

        default:
            /*
             * note: internal error here; the tlsprotocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public tlscipher getcipher()
        throws ioexception
    {

        switch (selectedciphersuite)
        {
        case ciphersuite.tls_psk_with_3des_ede_cbc_sha:
        case ciphersuite.tls_rsa_psk_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dhe_psk_with_3des_ede_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm._3des_ede_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_psk_with_aes_128_cbc_sha:
        case ciphersuite.tls_rsa_psk_with_aes_128_cbc_sha:
        case ciphersuite.tls_dhe_psk_with_aes_128_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_128_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_psk_with_aes_256_cbc_sha:
        case ciphersuite.tls_rsa_psk_with_aes_256_cbc_sha:
        case ciphersuite.tls_dhe_psk_with_aes_256_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_256_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_psk_with_null_sha:
        case ciphersuite.tls_rsa_psk_with_null_sha:
        case ciphersuite.tls_dhe_psk_with_null_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.null, macalgorithm.hmac_sha1);

        case ciphersuite.tls_psk_with_rc4_128_sha:
        case ciphersuite.tls_rsa_psk_with_rc4_128_sha:
        case ciphersuite.tls_dhe_psk_with_rc4_128_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.rc4_128, macalgorithm.hmac_sha1);

        default:
            /*
             * note: internal error here; the tlsprotocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    protected tlskeyexchange createpskkeyexchange(int keyexchange)
    {
        return new tlspskkeyexchange(keyexchange, supportedsignaturealgorithms, pskidentity);
    }
}
