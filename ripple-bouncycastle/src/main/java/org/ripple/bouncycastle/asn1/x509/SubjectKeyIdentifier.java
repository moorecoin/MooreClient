package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;

/**
 * the subjectkeyidentifier object.
 * <pre>
 * subjectkeyidentifier::= octet string
 * </pre>
 */
public class subjectkeyidentifier
    extends asn1object
{
    private byte[] keyidentifier;

    public static subjectkeyidentifier getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1octetstring.getinstance(obj, explicit));
    }

    public static subjectkeyidentifier getinstance(
        object obj)
    {
        if (obj instanceof subjectkeyidentifier)
        {
            return (subjectkeyidentifier)obj;
        }
        else if (obj != null)
        {
            return new subjectkeyidentifier(asn1octetstring.getinstance(obj));
        }

        return null;
    }

    public static subjectkeyidentifier fromextensions(extensions extensions)
    {
        return subjectkeyidentifier.getinstance(extensions.getextensionparsedvalue(extension.subjectkeyidentifier));
    }

    public subjectkeyidentifier(
        byte[] keyid)
    {
        this.keyidentifier = keyid;
    }

    protected subjectkeyidentifier(
        asn1octetstring keyid)
    {
        this.keyidentifier = keyid.getoctets();
    }

    public byte[] getkeyidentifier()
    {
        return keyidentifier;
    }

    public asn1primitive toasn1primitive()
    {
        return new deroctetstring(keyidentifier);
    }


    /**
     * calculates the keyidentifier using a sha1 hash over the bit string
     * from subjectpublickeyinfo as defined in rfc3280.
     *
     * @param spki the subject public key info.
     * @deprecated
     */
    public subjectkeyidentifier(
        subjectpublickeyinfo    spki)
    {
        this.keyidentifier = getdigest(spki);
    }

    /**
     * return a rfc 3280 type 1 key identifier. as in:
     * <pre>
     * (1) the keyidentifier is composed of the 160-bit sha-1 hash of the
     * value of the bit string subjectpublickey (excluding the tag,
     * length, and number of unused bits).
     * </pre>
     * @param keyinfo the key info object containing the subjectpublickey field.
     * @return the key identifier.
     * @deprecated use org.bouncycastle.cert.x509extensionutils.createsubjectkeyidentifier
     */
    public static subjectkeyidentifier createsha1keyidentifier(subjectpublickeyinfo keyinfo)
    {
        return new subjectkeyidentifier(keyinfo);
    }

    /**
     * return a rfc 3280 type 2 key identifier. as in:
     * <pre>
     * (2) the keyidentifier is composed of a four bit type field with
     * the value 0100 followed by the least significant 60 bits of the
     * sha-1 hash of the value of the bit string subjectpublickey.
     * </pre>
     * @param keyinfo the key info object containing the subjectpublickey field.
     * @return the key identifier.
     * @deprecated use org.bouncycastle.cert.x509extensionutils.createtruncatedsubjectkeyidentifier
     */
    public static subjectkeyidentifier createtruncatedsha1keyidentifier(subjectpublickeyinfo keyinfo)
    {
        byte[] dig = getdigest(keyinfo);
        byte[] id = new byte[8];

        system.arraycopy(dig, dig.length - 8, id, 0, id.length);

        id[0] &= 0x0f;
        id[0] |= 0x40;
        
        return new subjectkeyidentifier(id);
    }

    private static byte[] getdigest(subjectpublickeyinfo spki)
    {
        digest digest = new sha1digest();
        byte[]  resbuf = new byte[digest.getdigestsize()];

        byte[] bytes = spki.getpublickeydata().getbytes();
        digest.update(bytes, 0, bytes.length);
        digest.dofinal(resbuf, 0);
        return resbuf;
    }
}
