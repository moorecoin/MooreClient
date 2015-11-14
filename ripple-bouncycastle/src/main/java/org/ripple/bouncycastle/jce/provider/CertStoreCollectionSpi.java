package org.ripple.bouncycastle.jce.provider;

import java.security.invalidalgorithmparameterexception;
import java.security.cert.crl;
import java.security.cert.crlselector;
import java.security.cert.certselector;
import java.security.cert.certstoreexception;
import java.security.cert.certstoreparameters;
import java.security.cert.certstorespi;
import java.security.cert.certificate;
import java.security.cert.collectioncertstoreparameters;
import java.util.arraylist;
import java.util.collection;
import java.util.iterator;
import java.util.list;

public class certstorecollectionspi extends certstorespi
{
    private collectioncertstoreparameters params;

    public certstorecollectionspi(certstoreparameters params)
        throws invalidalgorithmparameterexception
    {
        super(params);

        if (!(params instanceof collectioncertstoreparameters))
        {
            throw new invalidalgorithmparameterexception("org.bouncycastle.jce.provider.certstorecollectionspi: parameter must be a collectioncertstoreparameters object\n" +  params.tostring());
        }

        this.params = (collectioncertstoreparameters)params;
    }

    public collection enginegetcertificates(
        certselector selector)
        throws certstoreexception 
    {
        list        col = new arraylist();
        iterator    iter = params.getcollection().iterator();

        if (selector == null)
        {
            while (iter.hasnext())
            {
                object obj = iter.next();

                if (obj instanceof certificate)
                {
                    col.add(obj);
                }
            }
        }
        else
        {
            while (iter.hasnext())
            {
                object obj = iter.next();

                if ((obj instanceof certificate) && selector.match((certificate)obj))
                {
                    col.add(obj);
                }
            }
        }
        
        return col;
    }
    

    public collection enginegetcrls(
        crlselector selector)
        throws certstoreexception 
    {
        list        col = new arraylist();
        iterator    iter = params.getcollection().iterator();

        if (selector == null)
        {
            while (iter.hasnext())
            {
                object obj = iter.next();

                if (obj instanceof crl)
                {
                    col.add(obj);
                }
            }
        }
        else
        {
            while (iter.hasnext())
            {
                object obj = iter.next();

                if ((obj instanceof crl) && selector.match((crl)obj))
                {
                    col.add(obj);
                }
            }
        }
        
        return col;
    }    
}
