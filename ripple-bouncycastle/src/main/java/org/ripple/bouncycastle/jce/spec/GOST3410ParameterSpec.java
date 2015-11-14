package org.ripple.bouncycastle.jce.spec;

import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.cryptopro.gost3410namedparameters;
import org.ripple.bouncycastle.asn1.cryptopro.gost3410paramsetparameters;
import org.ripple.bouncycastle.asn1.cryptopro.gost3410publickeyalgparameters;
import org.ripple.bouncycastle.jce.interfaces.gost3410params;

/**
 * parameterspec for a gost 3410-94 key.
 */
public class gost3410parameterspec
    implements algorithmparameterspec, gost3410params
{
    private gost3410publickeyparametersetspec keyparameters;
    private string                            keyparamsetoid;
    private string                            digestparamsetoid;
    private string                            encryptionparamsetoid;
    
    public gost3410parameterspec(
        string  keyparamsetid,
        string  digestparamsetoid,
        string  encryptionparamsetoid)
    {
        gost3410paramsetparameters  ecp = null;
        
        try
        {
            ecp = gost3410namedparameters.getbyoid(new asn1objectidentifier(keyparamsetid));
        }
        catch (illegalargumentexception e)
        {
            asn1objectidentifier oid = gost3410namedparameters.getoid(keyparamsetid);
            if (oid != null)
            {
                keyparamsetid = oid.getid();
                ecp = gost3410namedparameters.getbyoid(oid);
            }
        }
        
        if (ecp == null)
        {
            throw new illegalargumentexception("no key parameter set for passed in name/oid.");
        }

        this.keyparameters = new gost3410publickeyparametersetspec(
                                        ecp.getp(),
                                        ecp.getq(),
                                        ecp.geta());
        
        this.keyparamsetoid = keyparamsetid;
        this.digestparamsetoid = digestparamsetoid;
        this.encryptionparamsetoid = encryptionparamsetoid;
    }
    
    public gost3410parameterspec(
        string  keyparamsetid,
        string  digestparamsetoid)
    {
        this(keyparamsetid, digestparamsetoid, null);
    }
    
    public gost3410parameterspec(
        string  keyparamsetid)
    {
        this(keyparamsetid, cryptoproobjectidentifiers.gostr3411_94_cryptoproparamset.getid(), null);
    }
    
    public gost3410parameterspec(
        gost3410publickeyparametersetspec spec)
    {
        this.keyparameters = spec;
        this.digestparamsetoid = cryptoproobjectidentifiers.gostr3411_94_cryptoproparamset.getid();
        this.encryptionparamsetoid = null;
    }
    
    public string getpublickeyparamsetoid()
    {
        return this.keyparamsetoid;
    }

    public gost3410publickeyparametersetspec getpublickeyparameters()
    {
        return keyparameters;
    }
    
    public string getdigestparamsetoid()
    {
        return this.digestparamsetoid;
    }

    public string getencryptionparamsetoid()
    {
        return this.encryptionparamsetoid;
    }
    
    public boolean equals(object o)
    {
        if (o instanceof gost3410parameterspec)
        {
            gost3410parameterspec other = (gost3410parameterspec)o;
            
            return this.keyparameters.equals(other.keyparameters) 
                && this.digestparamsetoid.equals(other.digestparamsetoid)
                && (this.encryptionparamsetoid == other.encryptionparamsetoid
                    || (this.encryptionparamsetoid != null && this.encryptionparamsetoid.equals(other.encryptionparamsetoid)));
        }
        
        return false;
    }
    
    public int hashcode()
    {
        return this.keyparameters.hashcode() ^ this.digestparamsetoid.hashcode() 
                       ^ (this.encryptionparamsetoid != null ? this.encryptionparamsetoid.hashcode() : 0);
    }

    public static gost3410parameterspec frompublickeyalg(
        gost3410publickeyalgparameters params)
    {
        if (params.getencryptionparamset() != null)
        {
            return new gost3410parameterspec(params.getpublickeyparamset().getid(), params.getdigestparamset().getid(), params.getencryptionparamset().getid());
        }
        else
        {
            return new gost3410parameterspec(params.getpublickeyparamset().getid(), params.getdigestparamset().getid());
        }
    }
}
