package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.agreement.dhstandardgroups;
import org.ripple.bouncycastle.crypto.params.dhparameters;

public abstract class defaulttlsserver
    extends abstracttlsserver
{

    public defaulttlsserver()
    {
        super();
    }

    public defaulttlsserver(tlscipherfactory cipherfactory)
    {
        super(cipherfactory);
    }

    protected tlsencryptioncredentials getrsaencryptioncredentials()
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.internal_error);
    }

    protected tlssignercredentials getrsasignercredentials()
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.internal_error);
    }

    protected dhparameters getdhparameters()
    {
        return dhstandardgroups.rfc5114_1024_160;
    }

    protected int[] getciphersuites()
    {
        return new int[]{ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha,
            ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha, ciphersuite.tls_ecdhe_rsa_with_3des_ede_cbc_sha,
            ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha, ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha,
            ciphersuite.tls_dhe_rsa_with_3des_ede_cbc_sha, ciphersuite.tls_rsa_with_aes_256_cbc_sha,
            ciphersuite.tls_rsa_with_aes_128_cbc_sha, ciphersuite.tls_rsa_with_3des_ede_cbc_sha,};
    }

    public tlscredentials getcredentials()
        throws ioexception
    {

        switch (selectedciphersuite)
        {
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
            return getrsaencryptioncredentials();

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
        case ciphersuite.tls_ecdhe_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_gcm_sha384:
            return getrsasignercredentials();

        default:
            /*
             * note: internal error here; selected a key exchange we don't implement!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
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
             * note: internal error here; selected a key exchange we don't implement!
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
             * note: internal error here; selected a cipher suite we don't implement!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    protected tlskeyexchange createdhkeyexchange(int keyexchange)
    {
        return new tlsdhkeyexchange(keyexchange, supportedsignaturealgorithms, getdhparameters());
    }

    protected tlskeyexchange createdhekeyexchange(int keyexchange)
    {
        return new tlsdhekeyexchange(keyexchange, supportedsignaturealgorithms, getdhparameters());
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
