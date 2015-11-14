package org.ripple.bouncycastle.bcpg;

/**
 * basic pgp signature sub-packet tag types.
 */
public interface signaturesubpackettags 
{
    public static final int creation_time = 2;         // signature creation time
    public static final int expire_time = 3;           // signature expiration time
    public static final int exportable = 4;            // exportable certification
    public static final int trust_sig = 5;             // trust signature
    public static final int reg_exp = 6;               // regular expression
    public static final int revocable = 7;             // revocable
    public static final int key_expire_time = 9;       // key expiration time
    public static final int placeholder = 10;          // placeholder for backward compatibility
    public static final int preferred_sym_algs = 11;   // preferred symmetric algorithms
    public static final int revocation_key = 12;       // revocation key
    public static final int issuer_key_id = 16;        // issuer key id
    public static final int notation_data = 20;        // notation data
    public static final int preferred_hash_algs = 21;  // preferred hash algorithms
    public static final int preferred_comp_algs = 22;  // preferred compression algorithms
    public static final int key_server_prefs = 23;     // key server preferences
    public static final int preferred_key_serv = 24;   // preferred key server
    public static final int primary_user_id = 25;      // primary user id
    public static final int policy_url = 26;           // policy url
    public static final int key_flags = 27;            // key flags
    public static final int signer_user_id = 28;       // signer's user id
    public static final int revocation_reason = 29;    // reason for revocation
    public static final int features = 30;             // features
    public static final int signature_target = 31;     // signature target
    public static final int embedded_signature = 32;   // embedded signature
}
