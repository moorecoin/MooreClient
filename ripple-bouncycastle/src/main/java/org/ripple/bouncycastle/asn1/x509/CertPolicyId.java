package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;


/**
 * certpolicyid, used in the certificatepolicies and policymappings
 * x509v3 extensions.
 *
 * <pre>
 *     certpolicyid ::= object identifier
 * </pre>
 */
/**
 * certpolicyid, used in the certificatepolicies and policymappings
 * x509v3 extensions.
 *
 * <pre>
 *     certpolicyid ::= object identifier
 * </pre>
 */
public class certpolicyid
    extends asn1object
{
    private asn1objectidentifier id;

    private certpolicyid(asn1objectidentifier id)
    {
        this.id = id;
    }

    public static certpolicyid getinstance(object o)
    {
        if (o instanceof certpolicyid)
        {
            return (certpolicyid)o;
        }
        else if (o != null)
        {
            return new certpolicyid(asn1objectidentifier.getinstance(o));
        }

        return null;
    }

    public string getid()
    {
        return id.getid();
    }

    public asn1primitive toasn1primitive()
    {
        return id;
    }
}
