package org.ripple.bouncycastle.jce.interfaces;

import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;

public interface gost3410params
{

    public string getpublickeyparamsetoid();

    public string getdigestparamsetoid();

    public string getencryptionparamsetoid();
    
    public gost3410publickeyparametersetspec getpublickeyparameters();
}
