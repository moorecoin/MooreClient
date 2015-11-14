package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.hashtable;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;

public abstract class srptlsclient
    extends abstracttlsclient
{
    public static final integer ext_srp = integers.valueof(extensiontype.srp);

    protected byte[] identity;
    protected byte[] password;

    public srptlsclient(byte[] identity, byte[] password)
    {
        super();
        this.identity = arrays.clone(identity);
        this.password = arrays.clone(password);
    }

    public srptlsclient(tlscipherfactory cipherfactory, byte[] identity, byte[] password)
    {
        super(cipherfactory);
        this.identity = arrays.clone(identity);
        this.password = arrays.clone(password);
    }

    public int[] getciphersuites()
    {
        return new int[]{ciphersuite.tls_srp_sha_rsa_with_aes_256_cbc_sha,
            ciphersuite.tls_srp_sha_rsa_with_aes_128_cbc_sha, ciphersuite.tls_srp_sha_rsa_with_3des_ede_cbc_sha,
            ciphersuite.tls_srp_sha_with_aes_256_cbc_sha, ciphersuite.tls_srp_sha_with_aes_128_cbc_sha,
            ciphersuite.tls_srp_sha_with_3des_ede_cbc_sha,};
    }

    public hashtable getclientextensions()
        throws ioexception
    {

        hashtable clientextensions = super.getclientextensions();
        if (clientextensions == null)
        {
            clientextensions = new hashtable();
        }

        bytearrayoutputstream srpdata = new bytearrayoutputstream();
        tlsutils.writeopaque8(this.identity, srpdata);
        clientextensions.put(ext_srp, srpdata.tobytearray());

        return clientextensions;
    }

    public void processserverextensions(hashtable serverextensions)
        throws ioexception
    {
        // no explicit guidance in rfc 5054 here; we allow an optional empty extension from server
        if (serverextensions != null)
        {
            byte[] extvalue = (byte[])serverextensions.get(ext_srp);
            if (extvalue != null && extvalue.length > 0)
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
        case ciphersuite.tls_srp_sha_with_3des_ede_cbc_sha:
        case ciphersuite.tls_srp_sha_with_aes_128_cbc_sha:
        case ciphersuite.tls_srp_sha_with_aes_256_cbc_sha:
            return createsrpkeyexchange(keyexchangealgorithm.srp);

        case ciphersuite.tls_srp_sha_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_srp_sha_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_srp_sha_rsa_with_aes_256_cbc_sha:
            return createsrpkeyexchange(keyexchangealgorithm.srp_rsa);

        case ciphersuite.tls_srp_sha_dss_with_3des_ede_cbc_sha:
        case ciphersuite.tls_srp_sha_dss_with_aes_128_cbc_sha:
        case ciphersuite.tls_srp_sha_dss_with_aes_256_cbc_sha:
            return createsrpkeyexchange(keyexchangealgorithm.srp_dss);

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
        case ciphersuite.tls_srp_sha_with_3des_ede_cbc_sha:
        case ciphersuite.tls_srp_sha_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_srp_sha_dss_with_3des_ede_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm._3des_ede_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_srp_sha_with_aes_128_cbc_sha:
        case ciphersuite.tls_srp_sha_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_srp_sha_dss_with_aes_128_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_128_cbc, macalgorithm.hmac_sha1);

        case ciphersuite.tls_srp_sha_with_aes_256_cbc_sha:
        case ciphersuite.tls_srp_sha_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_srp_sha_dss_with_aes_256_cbc_sha:
            return cipherfactory.createcipher(context, encryptionalgorithm.aes_256_cbc, macalgorithm.hmac_sha1);

        default:
            /*
             * note: internal error here; the tlsprotocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    protected tlskeyexchange createsrpkeyexchange(int keyexchange)
    {
        return new tlssrpkeyexchange(keyexchange, supportedsignaturealgorithms, identity, password);
    }
}
