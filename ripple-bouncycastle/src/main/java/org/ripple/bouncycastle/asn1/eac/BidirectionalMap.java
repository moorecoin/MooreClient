package org.ripple.bouncycastle.asn1.eac;

import java.util.hashtable;

public class bidirectionalmap
    extends hashtable
{
    private static final long serialversionuid = -7457289971962812909l;

    hashtable reversemap = new hashtable();

    public object getreverse(object o)
    {
        return reversemap.get(o);
    }

    public object put(object key, object o)
    {
        reversemap.put(o, key);
        return super.put(key, o);
    }

}
