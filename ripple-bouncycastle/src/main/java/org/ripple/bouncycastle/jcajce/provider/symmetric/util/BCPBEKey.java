package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import javax.crypto.interfaces.pbekey;
import javax.crypto.spec.pbekeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

public class bcpbekey
    implements pbekey
{
    string              algorithm;
    asn1objectidentifier oid;
    int                 type;
    int                 digest;
    int                 keysize;
    int                 ivsize;
    cipherparameters    param;
    pbekeyspec          pbekeyspec;
    boolean             trywrong = false;

    /**
     * @param param
     */
    public bcpbekey(
        string algorithm,
        asn1objectidentifier oid,
        int type,
        int digest,
        int keysize,
        int ivsize,
        pbekeyspec pbekeyspec,
        cipherparameters param)
    {
        this.algorithm = algorithm;
        this.oid = oid;
        this.type = type;
        this.digest = digest;
        this.keysize = keysize;
        this.ivsize = ivsize;
        this.pbekeyspec = pbekeyspec;
        this.param = param;
    }

    public string getalgorithm()
    {
        return algorithm;
    }

    public string getformat()
    {
        return "raw";
    }

    public byte[] getencoded()
    {
        if (param != null)
        {
            keyparameter    kparam;
            
            if (param instanceof parameterswithiv)
            {
                kparam = (keyparameter)((parameterswithiv)param).getparameters();
            }
            else
            {
                kparam = (keyparameter)param;
            }
            
            return kparam.getkey();
        }
        else
        {
            if (type == pbe.pkcs12)
            {
                return pbeparametersgenerator.pkcs12passwordtobytes(pbekeyspec.getpassword());
            }
            else if (type == pbe.pkcs5s2_utf8)
            {
                return pbeparametersgenerator.pkcs5passwordtoutf8bytes(pbekeyspec.getpassword());
            }
            else
            {   
                return pbeparametersgenerator.pkcs5passwordtobytes(pbekeyspec.getpassword());
            }
        }
    }
    
    int gettype()
    {
        return type;
    }
    
    int getdigest()
    {
        return digest;
    }
    
    int getkeysize()
    {
        return keysize;
    }
    
    public int getivsize()
    {
        return ivsize;
    }
    
    public cipherparameters getparam()
    {
        return param;
    }

    /* (non-javadoc)
     * @see javax.crypto.interfaces.pbekey#getpassword()
     */
    public char[] getpassword()
    {
        return pbekeyspec.getpassword();
    }

    /* (non-javadoc)
     * @see javax.crypto.interfaces.pbekey#getsalt()
     */
    public byte[] getsalt()
    {
        return pbekeyspec.getsalt();
    }

    /* (non-javadoc)
     * @see javax.crypto.interfaces.pbekey#getiterationcount()
     */
    public int getiterationcount()
    {
        return pbekeyspec.getiterationcount();
    }
    
    public asn1objectidentifier getoid()
    {
        return oid;
    }
    
    public void settrywrongpkcs12zero(boolean trywrong)
    {
        this.trywrong = trywrong; 
    }
    
    boolean shouldtrywrongpkcs12()
    {
        return trywrong;
    }
}
