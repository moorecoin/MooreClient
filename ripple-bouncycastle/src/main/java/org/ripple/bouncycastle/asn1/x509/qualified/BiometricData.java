package org.ripple.bouncycastle.asn1.x509.qualified;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * the biometricdata object.
 * <pre>
 * biometricdata  ::=  sequence {
 *       typeofbiometricdata  typeofbiometricdata,
 *       hashalgorithm        algorithmidentifier,
 *       biometricdatahash    octet string,
 *       sourcedatauri        ia5string optional  }
 * </pre>
 */
public class biometricdata 
    extends asn1object
{
    private typeofbiometricdata typeofbiometricdata;
    private algorithmidentifier hashalgorithm;
    private asn1octetstring     biometricdatahash;
    private deria5string        sourcedatauri;
    
    public static biometricdata getinstance(
        object obj)
    {
        if (obj instanceof biometricdata)
        {
            return (biometricdata)obj;
        }

        if (obj != null)
        {
            return new biometricdata(asn1sequence.getinstance(obj));            
        }

        return null;
    }                
            
    private biometricdata(asn1sequence seq)
    {
        enumeration e = seq.getobjects();

        // typeofbiometricdata
        typeofbiometricdata = typeofbiometricdata.getinstance(e.nextelement());
        // hashalgorithm
        hashalgorithm = algorithmidentifier.getinstance(e.nextelement());
        // biometricdatahash
        biometricdatahash = asn1octetstring.getinstance(e.nextelement());
        // sourcedatauri
        if (e.hasmoreelements())
        {
            sourcedatauri = deria5string.getinstance(e.nextelement());
        }
    }
    
    public biometricdata(
        typeofbiometricdata typeofbiometricdata,
        algorithmidentifier hashalgorithm,
        asn1octetstring     biometricdatahash,
        deria5string        sourcedatauri)
    {
        this.typeofbiometricdata = typeofbiometricdata;
        this.hashalgorithm = hashalgorithm;
        this.biometricdatahash = biometricdatahash;
        this.sourcedatauri = sourcedatauri;
    }
    
    public biometricdata(
        typeofbiometricdata typeofbiometricdata,
        algorithmidentifier hashalgorithm,
        asn1octetstring     biometricdatahash)
    {
        this.typeofbiometricdata = typeofbiometricdata;
        this.hashalgorithm = hashalgorithm;
        this.biometricdatahash = biometricdatahash;
        this.sourcedatauri = null;
    }

    public typeofbiometricdata gettypeofbiometricdata()
    {
        return typeofbiometricdata;
    }
    
    public algorithmidentifier gethashalgorithm()
    {
        return hashalgorithm;
    }
    
    public asn1octetstring getbiometricdatahash()
    {
        return biometricdatahash;
    }
    
    public deria5string getsourcedatauri()
    {
        return sourcedatauri;
    }
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        seq.add(typeofbiometricdata);
        seq.add(hashalgorithm);
        seq.add(biometricdatahash); 
        
        if (sourcedatauri != null)
        {
            seq.add(sourcedatauri);
        }

        return new dersequence(seq);
    }
}
