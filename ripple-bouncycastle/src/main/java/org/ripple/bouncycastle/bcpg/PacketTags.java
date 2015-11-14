package org.ripple.bouncycastle.bcpg;

/**
 * basic pgp packet tag types.
 */
public interface packettags 
{
      public static final int reserved =  0 ;                //  reserved - a packet tag must not have this value
      public static final int public_key_enc_session = 1;    // public-key encrypted session key packet
      public static final int signature = 2;                 // signature packet
      public static final int symmetric_key_enc_session = 3; // symmetric-key encrypted session key packet
      public static final int one_pass_signature = 4 ;       // one-pass signature packet
      public static final int secret_key = 5;                // secret key packet
      public static final int public_key = 6 ;               // public key packet
      public static final int secret_subkey = 7;             // secret subkey packet
      public static final int compressed_data = 8;           // compressed data packet
      public static final int symmetric_key_enc = 9;         // symmetrically encrypted data packet
      public static final int marker = 10;                   // marker packet
      public static final int literal_data = 11;             // literal data packet
      public static final int trust = 12;                    // trust packet
      public static final int user_id = 13;                  // user id packet
      public static final int public_subkey = 14;            // public subkey packet
      public static final int user_attribute = 17;           // user attribute
      public static final int sym_enc_integrity_pro = 18;    // symmetric encrypted, integrity protected
      public static final int mod_detection_code = 19;       // modification detection code
      
      public static final int experimental_1 = 60;           // private or experimental values
      public static final int experimental_2 = 61;
      public static final int experimental_3 = 62;
      public static final int experimental_4 = 63;
}
