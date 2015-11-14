package org.ripple.bouncycastle.util;

import java.util.arraylist;
import java.util.collection;
import java.util.iterator;
import java.util.list;

/**
 * a simple collection backed store.
 */
public class collectionstore
    implements store
{
    private collection _local;

    /**
     * basic constructor.
     *
     * @param collection - initial contents for the store, this is copied.
     */
    public collectionstore(
        collection collection)
    {
        _local = new arraylist(collection);
    }

    /**
     * return the matches in the collection for the passed in selector.
     *
     * @param selector the selector to match against.
     * @return a possibly empty collection of matching objects.
     */
    public collection getmatches(selector selector)
    {
        if (selector == null)
        {
            return new arraylist(_local);
        }
        else
        {
            list col = new arraylist();
            iterator iter = _local.iterator();

            while (iter.hasnext())
            {
                object obj = iter.next();

                if (selector.match(obj))
                {
                    col.add(obj);
                }
            }

            return col;
        }
    }
}
