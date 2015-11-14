package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 5705
 */
public class exporterlabel
{
    /*
     * rfc 5246
     */
    public static final string client_finished = "client finished";
    public static final string server_finished = "server finished";
    public static final string master_secret = "master secret";
    public static final string key_expansion = "key expansion";

    /*
     * rfc 5216
     */
    public static final string client_eap_encryption = "client eap encryption";

    /*
     * rfc 5281
     */
    public static final string ttls_keying_material = "ttls keying material";
    public static final string ttls_challenge = "ttls challenge";

    /*
     * rfc 5764
     */
    public static final string dtls_srtp = "extractor-dtls_srtp";
}
