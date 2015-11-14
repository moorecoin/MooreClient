package org.ripple.bouncycastle.x509.extension;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.publickey;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509certificate;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.x509.authoritykeyidentifier;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.jce.principalutil;

/**
 * a high level authority key identifier.
 * @deprecated use jcax509extensionutils and authoritykeyidentifier.getinstance()
 */
public class authoritykeyidentifierstructure
    extends authoritykeyidentifier
{
    /**
     * constructor which will take the byte[] returned from getextensionvalue()
     * 
     * @param encodedvalue a der octet encoded string with the extension structure in it.
     * @throws ioexception on parsing errors.
     */
    public authoritykeyidentifierstructure(
        byte[]  encodedvalue)
        throws ioexception
    {
        super((asn1sequence)x509extensionutil.fromextensionvalue(encodedvalue));
    }

    /**
     * constructor which will take an extension
     *
     * @param extension a x509extension object containing an authoritykeyidentifier.
     * @deprecated use constructor that takes extension
     */
    public authoritykeyidentifierstructure(
        x509extension extension)
    {
        super((asn1sequence)extension.getparsedvalue());
    }

    /**
     * constructor which will take an extension
     *
     * @param extension a x509extension object containing an authoritykeyidentifier.
     */
    public authoritykeyidentifierstructure(
        extension extension)
    {
        super((asn1sequence)extension.getparsedvalue());
    }

    private static asn1sequence fromcertificate(
        x509certificate certificate)
        throws certificateparsingexception
    {
        try
        {
            if (certificate.getversion() != 3)
            {
                generalname          genname = new generalname(principalutil.getissuerx509principal(certificate));
                subjectpublickeyinfo info = new subjectpublickeyinfo(
                        (asn1sequence)new asn1inputstream(certificate.getpublickey().getencoded()).readobject());
                
                return (asn1sequence)new authoritykeyidentifier(
                               info, new generalnames(genname), certificate.getserialnumber()).toasn1object();
            }
            else
            {
                generalname             genname = new generalname(principalutil.getissuerx509principal(certificate));
                
                byte[]                  ext = certificate.getextensionvalue(x509extensions.subjectkeyidentifier.getid());
                
                if (ext != null)
                {
                    asn1octetstring     str = (asn1octetstring)x509extensionutil.fromextensionvalue(ext);
                
                    return (asn1sequence)new authoritykeyidentifier(
                                    str.getoctets(), new generalnames(genname), certificate.getserialnumber()).toasn1object();
                }
                else
                {
                    subjectpublickeyinfo info = new subjectpublickeyinfo(
                            (asn1sequence)new asn1inputstream(certificate.getpublickey().getencoded()).readobject());
                    
                    return (asn1sequence)new authoritykeyidentifier(
                            info, new generalnames(genname), certificate.getserialnumber()).toasn1object();
                }
            }
        }
        catch (exception e)
        {
            throw new certificateparsingexception("exception extracting certificate details: " + e.tostring());
        }
    }
    
    private static asn1sequence fromkey(
        publickey pubkey)
        throws invalidkeyexception
    {
        try
        {
            subjectpublickeyinfo info = new subjectpublickeyinfo(
                                        (asn1sequence)new asn1inputstream(pubkey.getencoded()).readobject());
        
            return (asn1sequence)new authoritykeyidentifier(info).toasn1object();
        }
        catch (exception e)
        {
            throw new invalidkeyexception("can't process key: " + e);
        }
    }
    
    /**
     * create an authoritykeyidentifier using the passed in certificate's public
     * key, issuer and serial number.
     * 
     * @param certificate the certificate providing the information.
     * @throws certificateparsingexception if there is a problem processing the certificate
     */
    public authoritykeyidentifierstructure(
        x509certificate certificate)
        throws certificateparsingexception
    {
        super(fromcertificate(certificate));
    }
    
    /**
     * create an authoritykeyidentifier using just the hash of the 
     * public key.
     * 
     * @param pubkey the key to generate the hash from.
     * @throws invalidkeyexception if there is a problem using the key.
     */
    public authoritykeyidentifierstructure(
        publickey pubkey) 
        throws invalidkeyexception
    {
        super(fromkey(pubkey));
    }
}
