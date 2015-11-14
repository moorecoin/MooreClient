package org.ripple.bouncycastle.jce;

import java.security.cert.certstoreparameters;
import java.util.collection;

public class multicertstoreparameters
    implements certstoreparameters
{
    private collection certstores;
    private boolean searchallstores;

    /**
     * create a parameters object which specifies searching of all the passed in stores.
     *
     * @param certstores certstores making up the multi certstore
     */
    public multicertstoreparameters(collection certstores)
    {
        this(certstores, true);
    }

    /**
     * create a parameters object which can be to used to make a multi store made up
     * of the passed in certstores. if the searchallstores parameter is false, any search on
     * the multi-store will terminate as soon as a search query produces a result.
     * 
     * @param certstores certstores making up the multi certstore
     * @param searchallstores true if all certstores should be searched on request, false if a result
     * should be returned on the first successful certstore query.
     */
    public multicertstoreparameters(collection certstores, boolean searchallstores)
    {
        this.certstores = certstores;
        this.searchallstores = searchallstores;
    }

    public collection getcertstores()
    {
        return certstores;
    }

    public boolean getsearchallstores()
    {
        return searchallstores;
    }

    public object clone()
    {
        return this;
    }
}
