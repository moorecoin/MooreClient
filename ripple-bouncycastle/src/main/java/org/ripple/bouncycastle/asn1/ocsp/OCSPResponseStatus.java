package org.ripple.bouncycastle.asn1.ocsp;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1enumerated;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;

public class ocspresponsestatus
    extends asn1object
{
    public static final int successful = 0;
    public static final int malformed_request = 1;
    public static final int internal_error = 2;
    public static final int try_later = 3;
    public static final int sig_required = 5;
    public static final int unauthorized = 6;

    private asn1enumerated value;

    /**
     * the ocspresponsestatus enumeration.
     * <pre>
     * ocspresponsestatus ::= enumerated {
     *     successful            (0),  --response has valid confirmations
     *     malformedrequest      (1),  --illegal confirmation request
     *     internalerror         (2),  --internal error in issuer
     *     trylater              (3),  --try again later
     *                                 --(4) is not used
     *     sigrequired           (5),  --must sign the request
     *     unauthorized          (6)   --request unauthorized
     * }
     * </pre>
     */
    public ocspresponsestatus(
        int value)
    {
        this(new asn1enumerated(value));
    }

    private ocspresponsestatus(
        asn1enumerated value)
    {
        this.value = value;
    }

    public static ocspresponsestatus getinstance(
        object  obj)
    {
        if (obj instanceof ocspresponsestatus)
        {
            return (ocspresponsestatus)obj;
        }
        else if (obj != null)
        {
            return new ocspresponsestatus(asn1enumerated.getinstance(obj));
        }

        return null;
    }

    public biginteger getvalue()
    {
        return value.getvalue();
    }

    public asn1primitive toasn1primitive()
    {
        return value;
    }
}
