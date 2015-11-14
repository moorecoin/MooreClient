package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.util.hashtable;

public abstract class defaulttlsclient
    extends abstracttlsclient
{

    protected int[] namedcurves;
    protected short[] clientecpointformats, serverecpointformats;

    public defaulttlsclient()
    {
        super();
    }

    public defaulttlsclient(tlscipherfactory cipherfactory)
    {
        super(cipherfactory);
    }

    public int[] getciphersuites()
    {
        return new int[]{ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha,
            ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha, ciphersuite.tls_ecdhe_rsa_with_3des_ede_cbc_sha,
            ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha, ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha,
            ciphersuite.tls_dhe_rsa_with_3des_ede_cbc_sha, ciphersuite.tls_rsa_with_aes_256_cbc_sha,
            ciphersuite.tls_rsa_with_aes_128_cbc_sha, ciphersuite.tls_rsa_with_3des_ede_cbc_sha,};
    }

    public hashtable getclientextensions()
        throws ioexception
    {

        hashtable clientextensions = super.getclientextensions();

        if (tlseccutils.containseccciphersuites(getciphersuites()))
        {
            /*
             * rfc 4492 5.1. a client that proposes ecc cipher suites in its clienthello message
             * appends these extensions (along with any others), enumerating the curves it supports
             * and the point formats it can parse. clients should send both the supported elliptic
             * curves extension and the supported point formats extension.
             */
            /*
             * todo could just add all the curves since we support them all, but users may not want
             * to use unnecessarily large fields. need configuration options.
             */
            this.namedcurves = new int[]{namedcurve.secp256r1, namedcurve.sect233r1, namedcurve.secp224r1,
                namedcurve.sect193r1, namedcurve.secp192r1, namedcurve.arbitrary_explicit_char2_curves,
                namedcurve.arbitrary_explicit_prime_curves};
            this.clientecpointformats = new short[]{ecpointformat.ansix962_compressed_char2,
                ecpointformat.ansix962_compressed_prime, ecpointformat.uncompressed};

            if (clientextensions == null)
            {
                clientextensions = new hashtable();
            }

            tlseccutils.addsupportedellipticcurvesextension(clientextensions, namedcurves);
            tlseccutils.addsupportedpointformatsextension(clientextensions, clientecpointformats);
        }

        return clientextensions;
    }

    public void processserverextensions(hashtable serverextensions)
        throws ioexception
    {

        super.processserverextensions(serverextensions);

        if (serverextensions != null)
        {
            int[] namedcurves = tlseccutils.getsupportedellipticcurvesextension(serverextensions);
            if (namedcurves != null)
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }

            this.serverecpointformats = tlseccutils.getsupportedpointformatsextension(serverextensions);
            if (this.serverecpointformats != null && !tlseccutils.iseccciphersuite(this.selectedciphersuite))
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
    }

    public tlskeyexchange getkeyexchange()
        throws ioexception
    {

        switch (selectedciphersuite)
        {
        case ciphersuite.tls_dh_dss_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dh_dss_with_aes_128_cbc_sha:
        case ciphersuite.tls_dh_dss_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dh_dss_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dh_dss_with_aes_256_cbc_sha:
        case ciphersuite.tls_dh_dss_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dh_dss_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dh_dss_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dh_dss_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dh_dss_with_seed_cbc_sha:
            return createdhkeyexchange(keyexchangealgorithm.dh_dss);

        case ciphersuite.tls_dh_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dh_rsa_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_seed_cbc_sha:
            return createdhkeyexchange(keyexchangealgorithm.dh_rsa);

        case ciphersuite.tls_dhe_dss_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_aes_128_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_256_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dhe_dss_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_seed_cbc_sha:
            return createdhekeyexchange(keyexchangealgorithm.dhe_dss);

        case ciphersuite.tls_dhe_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dhe_rsa_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_seed_cbc_sha:
            return createdhekeyexchange(keyexchangealgorithm.dhe_rsa);

        case ciphersuite.tls_ecdh_ecdsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_ecdsa_with_null_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_rc4_128_sha:
            return createecdhkeyexchange(keyexchangealgorithm.ecdh_ecdsa);

        case ciphersuite.tls_ecdh_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_rsa_with_null_sha:
        case ciphersuite.tls_ecdh_rsa_with_rc4_128_sha:
            return createecdhkeyexchange(keyexchangealgorithm.ecdh_rsa);

        case ciphersuite.tls_ecdhe_ecdsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_null_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_rc4_128_sha:
            return createecdhekeyexchange(keyexchangealgorithm.ecdhe_ecdsa);

        case ciphersuite.tls_ecdhe_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_null_sha:
        case ciphersuite.tls_ecdhe_rsa_with_rc4_128_sha:
            return createecdhekeyexchange(keyexchangealgorithm.ecdhe_rsa);

        case ciphersuite.tls_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_rsa_with_camellia_128_cbc_sha:
        case ciphersuite.tls_rsa_with_camellia_256_cbc_sha:
        case ciphersuite.tls_rsa_with_null_md5:
        case ciphersuite.tls_rsa_with_null_sha:
        case ciphersuite.tls_rsa_with_null_sha256:
        case ciphersuite.tls_rsa_with_rc4_128_md5:
        case ciphersuite.tls_rsa_with_rc4_128_sha:
        case ciphersuite.tls_rsa_with_seed_cbc_sha:
            return creatersakeyexchange();

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
        case ciphersuite.tls_dh_dss_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_3des_ede_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_rsa_with_3des_ede_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm._3des_ede_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_dh_dss_with_aes_128_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_aes_128_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_rsa_with_aes_128_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_128_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_dh_dss_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_rsa_with_aes_128_cbc_sha256:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_128_cbc, macalgorithm.hmac_sha256);

        case ciphersuite.tls_dh_dss_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_rsa_with_aes_128_gcm_sha256:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_128_gcm, macalgorithm._null);

        case ciphersuite.tls_dh_dss_with_aes_256_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_aes_256_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_rsa_with_aes_256_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_256_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_dh_dss_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_rsa_with_aes_256_cbc_sha256:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_256_cbc, macalgorithm.hmac_sha256);

        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha384:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_256_cbc, macalgorithm.hmac_sha384);

        case ciphersuite.tls_dh_dss_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dh_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dhe_dss_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_rsa_with_aes_256_gcm_sha384:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_256_gcm, macalgorithm._null);

        case ciphersuite.tls_dh_dss_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_camellia_128_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_camellia_128_cbc_sha:
        case ciphersuite.tls_rsa_with_camellia_128_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.camellia_128_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_dh_dss_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_camellia_256_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_camellia_256_cbc_sha:
        case ciphersuite.tls_rsa_with_camellia_256_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.camellia_256_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_rsa_with_null_md5:
            return cipherfactory.createcipher(context, encryptionalgorithm.null, macalgorithm.hmac_md5);

        case ciphersuite.tls_ecdh_ecdsa_with_null_sha:
        case ciphersuite.tls_ecdh_rsa_with_null_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_null_sha:
        case ciphersuite.tls_ecdhe_rsa_with_null_sha:
        case ciphersuite.tls_rsa_with_null_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.null, macalgorithm.hmac_sha1);

        case ciphersuite.tls_rsa_with_null_sha256:
            return cipherfactory.createcipher(context, encryptionalgorithm.null, macalgorithm.hmac_sha256);

        case ciphersuite.tls_rsa_with_rc4_128_md5:
            return cipherfactory.createcipher(context, encryptionalgorithm.rc4_128, macalgorithm.hmac_md5);

        case ciphersuite.tls_ecdh_ecdsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_rsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdhe_rsa_with_rc4_128_sha:
        case ciphersuite.tls_rsa_with_rc4_128_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.rc4_128, macalgorithm.hmac_sha1);

        case ciphersuite.tls_dh_dss_with_seed_cbc_sha:
        case ciphersuite.tls_dh_rsa_with_seed_cbc_sha:
        case ciphersuite.tls_dhe_dss_with_seed_cbc_sha:
        case ciphersuite.tls_dhe_rsa_with_seed_cbc_sha:
        case ciphersuite.tls_rsa_with_seed_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.seed_cbc, macalgorithm.hmac_sha1);

        default:
            /*
             * note: internal error here; the tlsprotocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    protected tlskeyexchange createdhkeyexchange(int keyexchange)
    {
        return new tlsdhkeyexchange(keyexchange, supportedsignaturealgorithms, null);
    }

    protected tlskeyexchange createdhekeyexchange(int keyexchange)
    {
        return new tlsdhekeyexchange(keyexchange, supportedsignaturealgorithms, null);
    }

    protected tlskeyexchange createecdhkeyexchange(int keyexchange)
    {
        return new tlsecdhkeyexchange(keyexchange, supportedsignaturealgorithms, namedcurves, clientecpointformats,
            serverecpointformats);
    }

    protected tlskeyexchange createecdhekeyexchange(int keyexchange)
    {
        return new tlsecdhekeyexchange(keyexchange, supportedsignaturealgorithms, namedcurves, clientecpointformats,
            serverecpointformats);
    }

    protected tlskeyexchange creatersakeyexchange()
    {
        return new tlsrsakeyexchange(supportedsignaturealgorithms);
    }
}
