package org.ripple.bouncycastle.jce.provider;

import java.security.invalidalgorithmparameterexception;
import java.security.cert.crlselector;
import java.security.cert.certselector;
import java.security.cert.certstore;
import java.security.cert.certstoreexception;
import java.security.cert.certstoreparameters;
import java.security.cert.certstorespi;
import java.util.arraylist;
import java.util.collection;
import java.util.collections;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.jce.multicertstoreparameters;

public class multicertstorespi
    extends certstorespi
{
    private multicertstoreparameters params;

    public multicertstorespi(certstoreparameters params)
        throws invalidalgorithmparameterexception
    {
        super(params);

        if (!(params instanceof multicertstoreparameters))
        {
            throw new invalidalgorithmparameterexception("org.bouncycastle.jce.provider.multicertstorespi: parameter must be a multicertstoreparameters object\n" +  params.tostring());
        }

        this.params = (multicertstoreparameters)params;
    }

    public collection enginegetcertificates(certselector certselector)
        throws certstoreexception
    {
        boolean searchallstores = params.getsearchallstores();
        iterator iter = params.getcertstores().iterator();
        list allcerts = searchallstores ? new arraylist() : collections.empty_list;

        while (iter.hasnext())
        {
            certstore store = (certstore)iter.next();
            collection certs = store.getcertificates(certselector);

            if (searchallstores)
            {
                allcerts.addall(certs);
            }
            else if (!certs.isempty())
            {
                return certs;
            }
        }

        return allcerts;
    }

    public collection enginegetcrls(crlselector crlselector)
        throws certstoreexception
    {
        boolean searchallstores = params.getsearchallstores();
        iterator iter = params.getcertstores().iterator();
        list allcrls = searchallstores ? new arraylist() : collections.empty_list;
        
        while (iter.hasnext())
        {
            certstore store = (certstore)iter.next();
            collection crls = store.getcrls(crlselector);

            if (searchallstores)
            {
                allcrls.addall(crls);
            }
            else if (!crls.isempty())
            {
                return crls;
            }
        }

        return allcrls;
    }
}
