package org.ripple.bouncycastle.jce;

import java.io.ioexception;
import java.security.cert.crlexception;
import java.security.cert.certificateencodingexception;
import java.security.cert.x509crl;
import java.security.cert.x509certificate;

import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x509.tbscertlist;
import org.ripple.bouncycastle.asn1.x509.tbscertificatestructure;
import org.ripple.bouncycastle.asn1.x509.x509name;

/**
 * a utility class that will extract x509principal objects from x.509 certificates.
 * <p>
 * use this in preference to trying to recreate a principal from a string, not all
 * dns are what they should be, so it's best to leave them encoded where they
 * can be.
 */
public class principalutil
{
    /**
     * return the issuer of the given cert as an x509principalobject.
     */
    public static x509principal getissuerx509principal(
        x509certificate cert)
        throws certificateencodingexception
    {
        try
        {
            tbscertificatestructure tbscert = tbscertificatestructure.getinstance(
                    asn1primitive.frombytearray(cert.gettbscertificate()));

            return new x509principal(x509name.getinstance(tbscert.getissuer()));
        }
        catch (ioexception e)
        {
            throw new certificateencodingexception(e.tostring());
        }
    }

    /**
     * return the subject of the given cert as an x509principalobject.
     */
    public static x509principal getsubjectx509principal(
        x509certificate cert)
        throws certificateencodingexception
    {
        try
        {
            tbscertificatestructure tbscert = tbscertificatestructure.getinstance(
                    asn1primitive.frombytearray(cert.gettbscertificate()));
            return new x509principal(x509name.getinstance(tbscert.getsubject()));
        }
        catch (ioexception e)
        {
            throw new certificateencodingexception(e.tostring());
        }
    }
    
    /**
     * return the issuer of the given crl as an x509principalobject.
     */
    public static x509principal getissuerx509principal(
        x509crl crl)
        throws crlexception
    {
        try
        {
            tbscertlist tbscertlist = tbscertlist.getinstance(
                asn1primitive.frombytearray(crl.gettbscertlist()));

            return new x509principal(x509name.getinstance(tbscertlist.getissuer()));
        }
        catch (ioexception e)
        {
            throw new crlexception(e.tostring());
        }
    }
}
