package org.ripple.bouncycastle.x509;

import java.util.arraylist;
import java.util.collection;

/**
 * this class contains a collection for collection based <code>x509store</code>s.
 * 
 * @see org.ripple.bouncycastle.x509.x509store
 * 
 */
public class x509collectionstoreparameters
    implements x509storeparameters
{
    private collection collection;

    /**
     * constructor.
     * <p>
     * the collection is copied.
     * </p>
     * 
     * @param collection
     *            the collection containing x.509 object types.
     * @throws nullpointerexception if <code>collection</code> is <code>null</code>.
     */
    public x509collectionstoreparameters(collection collection)
    {
        if (collection == null)
        {
            throw new nullpointerexception("collection cannot be null");
        }
        this.collection = collection;
    }

    /**
     * returns a shallow clone. the returned contents are not copied, so adding
     * or removing objects will effect this.
     * 
     * @return a shallow clone.
     */
    public object clone()
    {
        return new x509collectionstoreparameters(collection);
    }
    
    /**
     * returns a copy of the <code>collection</code>.
     * 
     * @return the <code>collection</code>. is never <code>null</code>.
     */
    public collection getcollection()
    {
        return new arraylist(collection);
    }
    
    /**
     * returns a formatted string describing the parameters.
     * 
     * @return a formatted string describing the parameters
     */
    public string tostring()
    {
        stringbuffer sb = new stringbuffer();
        sb.append("x509collectionstoreparameters: [\n");
        sb.append("  collection: " + collection + "\n");
        sb.append("]");
        return sb.tostring();
    }
}
