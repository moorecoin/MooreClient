package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class pkiarchiveoptions
    extends asn1object
    implements asn1choice
{
    public static final int encryptedprivkey = 0;
    public static final int keygenparameters = 1;
    public static final int archiveremgenprivkey = 2;

    private asn1encodable value;

    public static pkiarchiveoptions getinstance(object o)
    {
        if (o == null || o instanceof pkiarchiveoptions)
        {
            return (pkiarchiveoptions)o;
        }
        else if (o instanceof asn1taggedobject)
        {
            return new pkiarchiveoptions((asn1taggedobject)o);
        }

        throw new illegalargumentexception("unknown object: " + o);
    }

    private pkiarchiveoptions(asn1taggedobject tagged)
    {
        switch (tagged.gettagno())
        {
        case encryptedprivkey:
            value = encryptedkey.getinstance(tagged.getobject());
            break;
        case keygenparameters:
            value = asn1octetstring.getinstance(tagged, false);
            break;
        case archiveremgenprivkey:
            value = asn1boolean.getinstance(tagged, false);
            break;
        default:
            throw new illegalargumentexception("unknown tag number: " + tagged.gettagno());
        }
    }

    public pkiarchiveoptions(encryptedkey enckey)
    {
        this.value = enckey;
    }

    public pkiarchiveoptions(asn1octetstring keygenparameters)
    {
        this.value = keygenparameters;
    }

    public pkiarchiveoptions(boolean archiveremgenprivkey)
    {
        this.value = asn1boolean.getinstance(archiveremgenprivkey);
    }

    public int gettype()
    {
        if (value instanceof encryptedkey)
        {
            return encryptedprivkey;
        }

        if (value instanceof asn1octetstring)
        {
            return keygenparameters;
        }

        return archiveremgenprivkey;
    }

    public asn1encodable getvalue()
    {
        return value;
    }
    
    /**
     * <pre>
     *  pkiarchiveoptions ::= choice {
     *      encryptedprivkey     [0] encryptedkey,
     *      -- the actual value of the private key
     *      keygenparameters     [1] keygenparameters,
     *      -- parameters which allow the private key to be re-generated
     *      archiveremgenprivkey [2] boolean }
     *      -- set to true if sender wishes receiver to archive the private
     *      -- key of a key pair that the receiver generates in response to
     *      -- this request; set to false if no archival is desired.
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        if (value instanceof encryptedkey)
        {
            return new dertaggedobject(true, encryptedprivkey, value);  // choice
        }

        if (value instanceof asn1octetstring)
        {
            return new dertaggedobject(false, keygenparameters, value);
        }

        return new dertaggedobject(false, archiveremgenprivkey, value);
    }
}
