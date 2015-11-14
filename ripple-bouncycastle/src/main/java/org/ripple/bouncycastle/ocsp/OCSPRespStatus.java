package org.ripple.bouncycastle.ocsp;

public interface ocsprespstatus
{
    /**
     * note 4 is not used.
     */
    public static final int successful = 0;         // --response has valid confirmations
    public static final int malformed_request = 1;  // --illegal confirmation request
    public static final int internal_error = 2;     // --internal error in issuer
    public static final int try_later = 3;          // --try again later
    public static final int sigrequired = 5;        // --must sign the request
    public static final int unauthorized = 6;       //  --request unauthorized
}
