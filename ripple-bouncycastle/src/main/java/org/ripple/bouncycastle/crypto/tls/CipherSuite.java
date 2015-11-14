package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 2246 a.5
 */
public class ciphersuite
{

    public static final int tls_null_with_null_null = 0x0000;
    public static final int tls_rsa_with_null_md5 = 0x0001;
    public static final int tls_rsa_with_null_sha = 0x0002;
    public static final int tls_rsa_export_with_rc4_40_md5 = 0x0003;
    public static final int tls_rsa_with_rc4_128_md5 = 0x0004;
    public static final int tls_rsa_with_rc4_128_sha = 0x0005;
    public static final int tls_rsa_export_with_rc2_cbc_40_md5 = 0x0006;
    public static final int tls_rsa_with_idea_cbc_sha = 0x0007;
    public static final int tls_rsa_export_with_des40_cbc_sha = 0x0008;
    public static final int tls_rsa_with_des_cbc_sha = 0x0009;
    public static final int tls_rsa_with_3des_ede_cbc_sha = 0x000a;
    public static final int tls_dh_dss_export_with_des40_cbc_sha = 0x000b;
    public static final int tls_dh_dss_with_des_cbc_sha = 0x000c;
    public static final int tls_dh_dss_with_3des_ede_cbc_sha = 0x000d;
    public static final int tls_dh_rsa_export_with_des40_cbc_sha = 0x000e;
    public static final int tls_dh_rsa_with_des_cbc_sha = 0x000f;
    public static final int tls_dh_rsa_with_3des_ede_cbc_sha = 0x0010;
    public static final int tls_dhe_dss_export_with_des40_cbc_sha = 0x0011;
    public static final int tls_dhe_dss_with_des_cbc_sha = 0x0012;
    public static final int tls_dhe_dss_with_3des_ede_cbc_sha = 0x0013;
    public static final int tls_dhe_rsa_export_with_des40_cbc_sha = 0x0014;
    public static final int tls_dhe_rsa_with_des_cbc_sha = 0x0015;
    public static final int tls_dhe_rsa_with_3des_ede_cbc_sha = 0x0016;
    public static final int tls_dh_anon_export_with_rc4_40_md5 = 0x0017;
    public static final int tls_dh_anon_with_rc4_128_md5 = 0x0018;
    public static final int tls_dh_anon_export_with_des40_cbc_sha = 0x0019;
    public static final int tls_dh_anon_with_des_cbc_sha = 0x001a;
    public static final int tls_dh_anon_with_3des_ede_cbc_sha = 0x001b;

    /*
     * note: the cipher suite values { 0x00, 0x1c } and { 0x00, 0x1d } are reserved to avoid
     * collision with fortezza-based cipher suites in ssl 3.
     */

    /*
     * rfc 3268
     */
    public static final int tls_rsa_with_aes_128_cbc_sha = 0x002f;
    public static final int tls_dh_dss_with_aes_128_cbc_sha = 0x0030;
    public static final int tls_dh_rsa_with_aes_128_cbc_sha = 0x0031;
    public static final int tls_dhe_dss_with_aes_128_cbc_sha = 0x0032;
    public static final int tls_dhe_rsa_with_aes_128_cbc_sha = 0x0033;
    public static final int tls_dh_anon_with_aes_128_cbc_sha = 0x0034;
    public static final int tls_rsa_with_aes_256_cbc_sha = 0x0035;
    public static final int tls_dh_dss_with_aes_256_cbc_sha = 0x0036;
    public static final int tls_dh_rsa_with_aes_256_cbc_sha = 0x0037;
    public static final int tls_dhe_dss_with_aes_256_cbc_sha = 0x0038;
    public static final int tls_dhe_rsa_with_aes_256_cbc_sha = 0x0039;
    public static final int tls_dh_anon_with_aes_256_cbc_sha = 0x003a;

    /*
     * rfc 4132
     */
    public static final int tls_rsa_with_camellia_128_cbc_sha = 0x0041;
    public static final int tls_dh_dss_with_camellia_128_cbc_sha = 0x0042;
    public static final int tls_dh_rsa_with_camellia_128_cbc_sha = 0x0043;
    public static final int tls_dhe_dss_with_camellia_128_cbc_sha = 0x0044;
    public static final int tls_dhe_rsa_with_camellia_128_cbc_sha = 0x0045;
    public static final int tls_dh_anon_with_camellia_128_cbc_sha = 0x0046;
    public static final int tls_rsa_with_camellia_256_cbc_sha = 0x0084;
    public static final int tls_dh_dss_with_camellia_256_cbc_sha = 0x0085;
    public static final int tls_dh_rsa_with_camellia_256_cbc_sha = 0x0086;
    public static final int tls_dhe_dss_with_camellia_256_cbc_sha = 0x0087;
    public static final int tls_dhe_rsa_with_camellia_256_cbc_sha = 0x0088;
    public static final int tls_dh_anon_with_camellia_256_cbc_sha = 0x0089;

    /*
     * rfc 4162
     */
    public static final int tls_rsa_with_seed_cbc_sha = 0x0096;
    public static final int tls_dh_dss_with_seed_cbc_sha = 0x0097;
    public static final int tls_dh_rsa_with_seed_cbc_sha = 0x0098;
    public static final int tls_dhe_dss_with_seed_cbc_sha = 0x0099;
    public static final int tls_dhe_rsa_with_seed_cbc_sha = 0x009a;
    public static final int tls_dh_anon_with_seed_cbc_sha = 0x009b;

    /*
     * rfc 4279
     */
    public static final int tls_psk_with_rc4_128_sha = 0x008a;
    public static final int tls_psk_with_3des_ede_cbc_sha = 0x008b;
    public static final int tls_psk_with_aes_128_cbc_sha = 0x008c;
    public static final int tls_psk_with_aes_256_cbc_sha = 0x008d;
    public static final int tls_dhe_psk_with_rc4_128_sha = 0x008e;
    public static final int tls_dhe_psk_with_3des_ede_cbc_sha = 0x008f;
    public static final int tls_dhe_psk_with_aes_128_cbc_sha = 0x0090;
    public static final int tls_dhe_psk_with_aes_256_cbc_sha = 0x0091;
    public static final int tls_rsa_psk_with_rc4_128_sha = 0x0092;
    public static final int tls_rsa_psk_with_3des_ede_cbc_sha = 0x0093;
    public static final int tls_rsa_psk_with_aes_128_cbc_sha = 0x0094;
    public static final int tls_rsa_psk_with_aes_256_cbc_sha = 0x0095;

    /*
     * rfc 4492
     */
    public static final int tls_ecdh_ecdsa_with_null_sha = 0xc001;
    public static final int tls_ecdh_ecdsa_with_rc4_128_sha = 0xc002;
    public static final int tls_ecdh_ecdsa_with_3des_ede_cbc_sha = 0xc003;
    public static final int tls_ecdh_ecdsa_with_aes_128_cbc_sha = 0xc004;
    public static final int tls_ecdh_ecdsa_with_aes_256_cbc_sha = 0xc005;
    public static final int tls_ecdhe_ecdsa_with_null_sha = 0xc006;
    public static final int tls_ecdhe_ecdsa_with_rc4_128_sha = 0xc007;
    public static final int tls_ecdhe_ecdsa_with_3des_ede_cbc_sha = 0xc008;
    public static final int tls_ecdhe_ecdsa_with_aes_128_cbc_sha = 0xc009;
    public static final int tls_ecdhe_ecdsa_with_aes_256_cbc_sha = 0xc00a;
    public static final int tls_ecdh_rsa_with_null_sha = 0xc00b;
    public static final int tls_ecdh_rsa_with_rc4_128_sha = 0xc00c;
    public static final int tls_ecdh_rsa_with_3des_ede_cbc_sha = 0xc00d;
    public static final int tls_ecdh_rsa_with_aes_128_cbc_sha = 0xc00e;
    public static final int tls_ecdh_rsa_with_aes_256_cbc_sha = 0xc00f;
    public static final int tls_ecdhe_rsa_with_null_sha = 0xc010;
    public static final int tls_ecdhe_rsa_with_rc4_128_sha = 0xc011;
    public static final int tls_ecdhe_rsa_with_3des_ede_cbc_sha = 0xc012;
    public static final int tls_ecdhe_rsa_with_aes_128_cbc_sha = 0xc013;
    public static final int tls_ecdhe_rsa_with_aes_256_cbc_sha = 0xc014;
    public static final int tls_ecdh_anon_with_null_sha = 0xc015;
    public static final int tls_ecdh_anon_with_rc4_128_sha = 0xc016;
    public static final int tls_ecdh_anon_with_3des_ede_cbc_sha = 0xc017;
    public static final int tls_ecdh_anon_with_aes_128_cbc_sha = 0xc018;
    public static final int tls_ecdh_anon_with_aes_256_cbc_sha = 0xc019;

    /*
     * rfc 4785
     */
    public static final int tls_psk_with_null_sha = 0x002c;
    public static final int tls_dhe_psk_with_null_sha = 0x002d;
    public static final int tls_rsa_psk_with_null_sha = 0x002e;

    /*
     * rfc 5054
     */
    public static final int tls_srp_sha_with_3des_ede_cbc_sha = 0xc01a;
    public static final int tls_srp_sha_rsa_with_3des_ede_cbc_sha = 0xc01b;
    public static final int tls_srp_sha_dss_with_3des_ede_cbc_sha = 0xc01c;
    public static final int tls_srp_sha_with_aes_128_cbc_sha = 0xc01d;
    public static final int tls_srp_sha_rsa_with_aes_128_cbc_sha = 0xc01e;
    public static final int tls_srp_sha_dss_with_aes_128_cbc_sha = 0xc01f;
    public static final int tls_srp_sha_with_aes_256_cbc_sha = 0xc020;
    public static final int tls_srp_sha_rsa_with_aes_256_cbc_sha = 0xc021;
    public static final int tls_srp_sha_dss_with_aes_256_cbc_sha = 0xc022;

    /*
     * rfc 5246
     */
    public static final int tls_rsa_with_null_sha256 = 0x003b;
    public static final int tls_rsa_with_aes_128_cbc_sha256 = 0x003c;
    public static final int tls_rsa_with_aes_256_cbc_sha256 = 0x003d;
    public static final int tls_dh_dss_with_aes_128_cbc_sha256 = 0x003e;
    public static final int tls_dh_rsa_with_aes_128_cbc_sha256 = 0x003f;
    public static final int tls_dhe_dss_with_aes_128_cbc_sha256 = 0x0040;
    public static final int tls_dhe_rsa_with_aes_128_cbc_sha256 = 0x0067;
    public static final int tls_dh_dss_with_aes_256_cbc_sha256 = 0x0068;
    public static final int tls_dh_rsa_with_aes_256_cbc_sha256 = 0x0069;
    public static final int tls_dhe_dss_with_aes_256_cbc_sha256 = 0x006a;
    public static final int tls_dhe_rsa_with_aes_256_cbc_sha256 = 0x006b;
    public static final int tls_dh_anon_with_aes_128_cbc_sha256 = 0x006c;
    public static final int tls_dh_anon_with_aes_256_cbc_sha256 = 0x006d;

    /*
     * rfc 5288
     */
    public static final int tls_rsa_with_aes_128_gcm_sha256 = 0x009c;
    public static final int tls_rsa_with_aes_256_gcm_sha384 = 0x009d;
    public static final int tls_dhe_rsa_with_aes_128_gcm_sha256 = 0x009e;
    public static final int tls_dhe_rsa_with_aes_256_gcm_sha384 = 0x009f;
    public static final int tls_dh_rsa_with_aes_128_gcm_sha256 = 0x00a0;
    public static final int tls_dh_rsa_with_aes_256_gcm_sha384 = 0x00a1;
    public static final int tls_dhe_dss_with_aes_128_gcm_sha256 = 0x00a2;
    public static final int tls_dhe_dss_with_aes_256_gcm_sha384 = 0x00a3;
    public static final int tls_dh_dss_with_aes_128_gcm_sha256 = 0x00a4;
    public static final int tls_dh_dss_with_aes_256_gcm_sha384 = 0x00a5;
    public static final int tls_dh_anon_with_aes_128_gcm_sha256 = 0x00a6;
    public static final int tls_dh_anon_with_aes_256_gcm_sha384 = 0x00a7;

    /*
     * rfc 5289
     */
    public static final int tls_ecdhe_ecdsa_with_aes_128_cbc_sha256 = 0xc023;
    public static final int tls_ecdhe_ecdsa_with_aes_256_cbc_sha384 = 0xc024;
    public static final int tls_ecdh_ecdsa_with_aes_128_cbc_sha256 = 0xc025;
    public static final int tls_ecdh_ecdsa_with_aes_256_cbc_sha384 = 0xc026;
    public static final int tls_ecdhe_rsa_with_aes_128_cbc_sha256 = 0xc027;
    public static final int tls_ecdhe_rsa_with_aes_256_cbc_sha384 = 0xc028;
    public static final int tls_ecdh_rsa_with_aes_128_cbc_sha256 = 0xc029;
    public static final int tls_ecdh_rsa_with_aes_256_cbc_sha384 = 0xc02a;
    public static final int tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b;
    public static final int tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c;
    public static final int tls_ecdh_ecdsa_with_aes_128_gcm_sha256 = 0xc02d;
    public static final int tls_ecdh_ecdsa_with_aes_256_gcm_sha384 = 0xc02e;
    public static final int tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f;
    public static final int tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030;
    public static final int tls_ecdh_rsa_with_aes_128_gcm_sha256 = 0xc031;
    public static final int tls_ecdh_rsa_with_aes_256_gcm_sha384 = 0xc032;

    /*
     * rfc 5746
     */
    public static final int tls_empty_renegotiation_info_scsv = 0x00ff;
}
