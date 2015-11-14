package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.publickey;
import java.security.signatureexception;
import java.security.cert.certificateexception;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatenotyetvalidexception;
import java.security.cert.x509extension;
import java.util.date;

/**
 * interface for an x.509 attribute certificate.
 */
public interface x509attributecertificate
    extends x509extension
{   
    /**
     * return the version number for the certificate.
     * 
     * @return the version number.
     */
    public int getversion();
    
    /**
     * return the serial number for the certificate.
     * 
     * @return the serial number.
     */
    public biginteger getserialnumber();
    
    /**
     * return the date before which the certificate is not valid.
     * 
     * @return the "not valid before" date.
     */
    public date getnotbefore();
    
    /**
     * return the date after which the certificate is not valid.
     * 
     * @return the "not valid afer" date.
     */
    public date getnotafter();
    
    /**
     * return the holder of the certificate.
     * 
     * @return the holder.
     */
    public attributecertificateholder getholder();
    
    /**
     * return the issuer details for the certificate.
     * 
     * @return the issuer details.
     */
    public attributecertificateissuer getissuer();
    
    /**
     * return the attributes contained in the attribute block in the certificate.
     * 
     * @return an array of attributes.
     */
    public x509attribute[] getattributes();
    
    /**
     * return the attributes with the same type as the passed in oid.
     * 
     * @param oid the object identifier we wish to match.
     * @return an array of matched attributes, null if there is no match.
     */
    public x509attribute[] getattributes(string oid);
    
    public boolean[] getissueruniqueid();
    
    public void checkvalidity()
        throws certificateexpiredexception, certificatenotyetvalidexception;
    
    public void checkvalidity(date date)
        throws certificateexpiredexception, certificatenotyetvalidexception;
    
    public byte[] getsignature();
    
    public void verify(publickey key, string provider)
            throws certificateexception, nosuchalgorithmexception,
            invalidkeyexception, nosuchproviderexception, signatureexception;
    
    /**
     * return an asn.1 encoded byte array representing the attribute certificate.
     * 
     * @return an asn.1 encoded byte array.
     * @throws ioexception if the certificate cannot be encoded.
     */
    public byte[] getencoded()
        throws ioexception;
}
