package org.ripple.bouncycastle.x509.extension;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.publickey;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.x509.subjectkeyidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

/**
 * a high level subject key identifier.
 * @deprecated use jcax509extensionutils andsubjectkeyidentifier.getinstance()
 */
public class subjectkeyidentifierstructure
    extends subjectkeyidentifier
{
    /**
     * constructor which will take the byte[] returned from getextensionvalue()
     * 
     * @param encodedvalue a der octet encoded string with the extension structure in it.
     * @throws ioexception on parsing errors.
     */
    public subjectkeyidentifierstructure(
        byte[]  encodedvalue)
        throws ioexception
    {
        super((asn1octetstring)x509extensionutil.fromextensionvalue(encodedvalue));
    }
    
    private static asn1octetstring frompublickey(
        publickey pubkey)
        throws invalidkeyexception
    {
        try
        {
            subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(pubkey.getencoded());

            return (asn1octetstring)(new subjectkeyidentifier(info).toasn1object());
        }
        catch (exception e)
        {
            throw new invalidkeyexception("exception extracting key details: " + e.tostring());
        }
    }
    
    public subjectkeyidentifierstructure(
        publickey pubkey)
        throws invalidkeyexception
    {
        super(frompublickey(pubkey));
    }
}
