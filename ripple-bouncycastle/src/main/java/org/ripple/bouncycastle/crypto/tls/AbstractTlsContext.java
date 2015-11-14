package org.ripple.bouncycastle.crypto.tls;

import java.security.securerandom;

abstract class abstracttlscontext
    implements tlscontext
{

    private securerandom securerandom;
    private securityparameters securityparameters;

    private protocolversion clientversion = null;
    private protocolversion serverversion = null;
    private object userobject = null;

    abstracttlscontext(securerandom securerandom, securityparameters securityparameters)
    {
        this.securerandom = securerandom;
        this.securityparameters = securityparameters;
    }

    public securerandom getsecurerandom()
    {
        return securerandom;
    }

    public securityparameters getsecurityparameters()
    {
        return securityparameters;
    }

    public protocolversion getclientversion()
    {
        return clientversion;
    }

    public void setclientversion(protocolversion clientversion)
    {
        this.clientversion = clientversion;
    }

    public protocolversion getserverversion()
    {
        return serverversion;
    }

    public void setserverversion(protocolversion serverversion)
    {
        this.serverversion = serverversion;
    }

    public object getuserobject()
    {
        return userobject;
    }

    public void setuserobject(object userobject)
    {
        this.userobject = userobject;
    }

    public byte[] exportkeyingmaterial(string asciilabel, byte[] context_value, int length)
    {

        securityparameters sp = getsecurityparameters();
        byte[] cr = sp.getclientrandom(), sr = sp.getserverrandom();

        int seedlength = cr.length + sr.length;
        if (context_value != null)
        {
            seedlength += (2 + context_value.length);
        }

        byte[] seed = new byte[seedlength];
        int seedpos = 0;

        system.arraycopy(cr, 0, seed, seedpos, cr.length);
        seedpos += cr.length;
        system.arraycopy(sr, 0, seed, seedpos, sr.length);
        seedpos += sr.length;
        if (context_value != null)
        {
            tlsutils.writeuint16(context_value.length, seed, seedpos);
            seedpos += 2;
            system.arraycopy(context_value, 0, seed, seedpos, context_value.length);
            seedpos += context_value.length;
        }

        if (seedpos != seedlength)
        {
            throw new illegalstateexception("error in calculation of seed for export");
        }

        return tlsutils.prf(this, sp.getmastersecret(), asciilabel, seed, length);
    }
}
