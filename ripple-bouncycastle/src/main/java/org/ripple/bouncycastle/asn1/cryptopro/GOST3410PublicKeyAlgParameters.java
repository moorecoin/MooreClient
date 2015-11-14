package org.ripple.bouncycastle.asn1.cryptopro;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class gost3410publickeyalgparameters
    extends asn1object
{
    private asn1objectidentifier  publickeyparamset;
    private asn1objectidentifier  digestparamset;
    private asn1objectidentifier  encryptionparamset;
    
    public static gost3410publickeyalgparameters getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static gost3410publickeyalgparameters getinstance(
        object obj)
    {
        if (obj instanceof gost3410publickeyalgparameters)
        {
            return (gost3410publickeyalgparameters)obj;
        }

        if(obj != null)
        {
            return new gost3410publickeyalgparameters(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    public gost3410publickeyalgparameters(
        asn1objectidentifier  publickeyparamset,
        asn1objectidentifier  digestparamset)
    {
        this.publickeyparamset = publickeyparamset;
        this.digestparamset = digestparamset;
        this.encryptionparamset = null;
    }

    public gost3410publickeyalgparameters(
        asn1objectidentifier  publickeyparamset,
        asn1objectidentifier  digestparamset,
        asn1objectidentifier  encryptionparamset)
    {
        this.publickeyparamset = publickeyparamset;
        this.digestparamset = digestparamset;
        this.encryptionparamset = encryptionparamset;
    }

    public gost3410publickeyalgparameters(
        asn1sequence  seq)
    {
        this.publickeyparamset = (asn1objectidentifier)seq.getobjectat(0);
        this.digestparamset = (asn1objectidentifier)seq.getobjectat(1);
        
        if (seq.size() > 2)
        {
            this.encryptionparamset = (asn1objectidentifier)seq.getobjectat(2);
        }
    }

    public asn1objectidentifier getpublickeyparamset()
    {
        return publickeyparamset;
    }

    public asn1objectidentifier getdigestparamset()
    {
        return digestparamset;
    }

    public asn1objectidentifier getencryptionparamset()
    {
        return encryptionparamset;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(publickeyparamset);
        v.add(digestparamset);
        
        if (encryptionparamset != null)
        {
            v.add(encryptionparamset);
        }

        return new dersequence(v);
    }
}
