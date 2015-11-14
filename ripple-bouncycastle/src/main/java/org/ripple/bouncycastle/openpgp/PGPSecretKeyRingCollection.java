package org.ripple.bouncycastle.openpgp;

import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.util.strings;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.arraylist;
import java.util.collection;
import java.util.hashmap;
import java.util.iterator;
import java.util.list;
import java.util.map;

/**
 * often a pgp key ring file is made up of a succession of master/sub-key key rings.
 * if you want to read an entire secret key file in one hit this is the class for you.
 */
public class pgpsecretkeyringcollection 
{
    private map    secretrings = new hashmap();
    private list   order = new arraylist();
    
    private pgpsecretkeyringcollection(
        map     secretrings,
        list    order)
    {
        this.secretrings = secretrings;
        this.order = order;
    }
    
    public pgpsecretkeyringcollection(
        byte[]    encoding)
        throws ioexception, pgpexception
    {
        this(new bytearrayinputstream(encoding));
    }

    /**
     * build a pgpsecretkeyringcollection from the passed in input stream.
     *
     * @param in  input stream containing data
     * @throws ioexception if a problem parsinh the base stream occurs
     * @throws pgpexception if an object is encountered which isn't a pgpsecretkeyring
     */
    public pgpsecretkeyringcollection(
        inputstream    in)
        throws ioexception, pgpexception
    {
        pgpobjectfactory    pgpfact = new pgpobjectfactory(in);
        object              obj;

        while ((obj = pgpfact.nextobject()) != null)
        {
            if (!(obj instanceof pgpsecretkeyring))
            {
                throw new pgpexception(obj.getclass().getname() + " found where pgpsecretkeyring expected");
            }
            
            pgpsecretkeyring    pgpsecret = (pgpsecretkeyring)obj;
            long                key = new long(pgpsecret.getpublickey().getkeyid());
            
            secretrings.put(key, pgpsecret);
            order.add(key);
        }
    }
    
    public pgpsecretkeyringcollection(
        collection    collection)
        throws ioexception, pgpexception
    {
        iterator                it = collection.iterator();

        while (it.hasnext())
        {
            pgpsecretkeyring    pgpsecret = (pgpsecretkeyring)it.next();
            long                key = new long(pgpsecret.getpublickey().getkeyid());
            
            secretrings.put(key, pgpsecret);
            order.add(key);
        }
    }
    
    /**
     * return the number of rings in this collection.
     * 
     * @return size of the collection
     */
    public int size()
    {
        return order.size();
    }
    
    /**
     * return the secret key rings making up this collection.
     */
    public iterator getkeyrings()
    {
        return secretrings.values().iterator();
    }

    /**
     * return an iterator of the key rings associated with the passed in userid.
     * 
     * @param userid the user id to be matched.
     * @return an iterator (possibly empty) of key rings which matched.
     * @throws pgpexception
     */
    public iterator getkeyrings(
        string    userid) 
        throws pgpexception
    {   
        return getkeyrings(userid, false, false);
    }

    /**
     * return an iterator of the key rings associated with the passed in userid.
     * <p>
     * 
     * @param userid the user id to be matched.
     * @param matchpartial if true userid need only be a substring of an actual id string to match.
     * @return an iterator (possibly empty) of key rings which matched.
     * @throws pgpexception
     */
    public iterator getkeyrings(
        string    userid,
        boolean   matchpartial) 
        throws pgpexception
    {
        return getkeyrings(userid, matchpartial, false);
    }

    /**
     * return an iterator of the key rings associated with the passed in userid.
     * <p>
     * 
     * @param userid the user id to be matched.
     * @param matchpartial if true userid need only be a substring of an actual id string to match.
     * @param ignorecase if true case is ignored in user id comparisons.
     * @return an iterator (possibly empty) of key rings which matched.
     * @throws pgpexception
     */
    public iterator getkeyrings(
        string    userid,
        boolean   matchpartial,
        boolean   ignorecase) 
        throws pgpexception
    {
        iterator    it = this.getkeyrings();
        list        rings = new arraylist();

        if (ignorecase)
        {
            userid = strings.tolowercase(userid);
        }

        while (it.hasnext())
        {
            pgpsecretkeyring secring = (pgpsecretkeyring)it.next();
            iterator         uit = secring.getsecretkey().getuserids();
            
            while (uit.hasnext())
            {
                string next = (string)uit.next();
                if (ignorecase)
                {
                    next = strings.tolowercase(next);
                }

                if (matchpartial)
                {
                    if (next.indexof(userid) > -1)
                    {
                        rings.add(secring);
                    }
                }
                else
                {
                    if (next.equals(userid))
                    {
                        rings.add(secring);
                    }
                }
            }
        }
    
        return rings.iterator();
    }

    /**
     * return the pgp secret key associated with the given key id.
     * 
     * @param keyid
     * @return the secret key
     * @throws pgpexception
     */
    public pgpsecretkey getsecretkey(
        long        keyid) 
        throws pgpexception
    {    
        iterator    it = this.getkeyrings();
        
        while (it.hasnext())
        {
            pgpsecretkeyring    secring = (pgpsecretkeyring)it.next();
            pgpsecretkey        sec = secring.getsecretkey(keyid);
            
            if (sec != null)
            {
                return sec;
            }
        }
    
        return null;
    }
    
    /**
     * return the secret key ring which contains the key referred to by keyid.
     * 
     * @param keyid
     * @return the secret key ring
     * @throws pgpexception
     */
    public pgpsecretkeyring getsecretkeyring(
        long    keyid) 
        throws pgpexception
    {
        long    id = new long(keyid);
        
        if (secretrings.containskey(id))
        {
            return (pgpsecretkeyring)secretrings.get(id);
        }
        
        iterator    it = this.getkeyrings();
        
        while (it.hasnext())
        {
            pgpsecretkeyring    secretring = (pgpsecretkeyring)it.next();
            pgpsecretkey        secret = secretring.getsecretkey(keyid);
            
            if (secret != null)
            {
                return secretring;
            }
        }
    
        return null;
    }

    /**
     * return true if a key matching the passed in key id is present, false otherwise.
     *
     * @param keyid key id to look for.
     * @return true if keyid present, false otherwise.
     */
    public boolean contains(long keyid)
        throws pgpexception
    {
        return getsecretkey(keyid) != null;
    }

    public byte[] getencoded() 
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        this.encode(bout);
        
        return bout.tobytearray();
    }
    
    public void encode(
        outputstream    outstream) 
        throws ioexception
    {
        bcpgoutputstream    out;
        
        if (outstream instanceof bcpgoutputstream)
        {
            out = (bcpgoutputstream)outstream;
        }
        else
        {
            out = new bcpgoutputstream(outstream);
        }

        iterator    it = order.iterator();
        while (it.hasnext())
        {
            pgpsecretkeyring    sr = (pgpsecretkeyring)secretrings.get(it.next());
            
            sr.encode(out);
        }
    }
    
    /**
     * return a new collection object containing the contents of the passed in collection and
     * the passed in secret key ring.
     * 
     * @param ringcollection the collection the ring to be added to.
     * @param secretkeyring the key ring to be added.
     * @return a new collection merging the current one with the passed in ring.
     * @exception illegalargumentexception if the keyid for the passed in ring is already present.
     */
    public static pgpsecretkeyringcollection addsecretkeyring(
        pgpsecretkeyringcollection ringcollection,
        pgpsecretkeyring           secretkeyring)
    {
        long        key = new long(secretkeyring.getpublickey().getkeyid());
        
        if (ringcollection.secretrings.containskey(key))
        {
            throw new illegalargumentexception("collection already contains a key with a keyid for the passed in ring.");
        }
        
        map     newsecretrings = new hashmap(ringcollection.secretrings);
        list    neworder = new arraylist(ringcollection.order); 
        
        newsecretrings.put(key, secretkeyring);
        neworder.add(key);
        
        return new pgpsecretkeyringcollection(newsecretrings, neworder);
    }
    
    /**
     * return a new collection object containing the contents of this collection with
     * the passed in secret key ring removed.
     * 
     * @param ringcollection the collection the ring to be removed from.
     * @param secretkeyring the key ring to be removed.
     * @return a new collection merging the current one with the passed in ring.
     * @exception illegalargumentexception if the keyid for the passed in ring is not present.
     */
    public static pgpsecretkeyringcollection removesecretkeyring(
        pgpsecretkeyringcollection ringcollection,
        pgpsecretkeyring           secretkeyring)
    {
        long        key = new long(secretkeyring.getpublickey().getkeyid());
        
        if (!ringcollection.secretrings.containskey(key))
        {
            throw new illegalargumentexception("collection does not contain a key with a keyid for the passed in ring.");
        }
        
        map     newsecretrings = new hashmap(ringcollection.secretrings);
        list    neworder = new arraylist(ringcollection.order); 
        
        newsecretrings.remove(key);
        
        for (int i = 0; i < neworder.size(); i++)
        {
            long    r = (long)neworder.get(i);
            
            if (r.longvalue() == key.longvalue())
            {
                neworder.remove(i);
                break;
            }
        }
        
        return new pgpsecretkeyringcollection(newsecretrings, neworder);
    }
}
