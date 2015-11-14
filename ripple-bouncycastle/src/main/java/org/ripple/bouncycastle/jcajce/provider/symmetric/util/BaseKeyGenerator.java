package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.keygeneratorspi;
import javax.crypto.secretkey;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class basekeygenerator
    extends keygeneratorspi
{
    protected string                algname;
    protected int                   keysize;
    protected int                   defaultkeysize;
    protected cipherkeygenerator    engine;

    protected boolean               uninitialised = true;

    protected basekeygenerator(
        string algname,
        int defaultkeysize,
        cipherkeygenerator engine)
    {
        this.algname = algname;
        this.keysize = this.defaultkeysize = defaultkeysize;
        this.engine = engine;
    }

    protected void engineinit(
        algorithmparameterspec  params,
        securerandom            random)
    throws invalidalgorithmparameterexception
    {
        throw new invalidalgorithmparameterexception("not implemented");
    }

    protected void engineinit(
        securerandom    random)
    {
        if (random != null)
        {
            engine.init(new keygenerationparameters(random, defaultkeysize));
            uninitialised = false;
        }
    }

    protected void engineinit(
        int             keysize,
        securerandom    random)
    {
        try
        {
            if (random == null)
            {
                random = new securerandom();
            }
            engine.init(new keygenerationparameters(random, keysize));
            uninitialised = false;
        }
        catch (illegalargumentexception e)
        {
            throw new invalidparameterexception(e.getmessage());
        }
    }

    protected secretkey enginegeneratekey()
    {
        if (uninitialised)
        {
            engine.init(new keygenerationparameters(new securerandom(), defaultkeysize));
            uninitialised = false;
        }

        return new secretkeyspec(engine.generatekey(), algname);
    }
}
