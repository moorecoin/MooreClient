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
 * if you want to read an entire public key file in one hit this is the class for you.
 */
public class pgppublickeyringcollection 
{
    private map   pubrings = new hashmap();
    private list  order = new arraylist();
    
    private pgppublickeyringcollection(
        map     pubrings,
        list    order)
    {
        this.pubrings = pubrings;
        this.order = order;
    }
    
    public pgppublickeyringcollection(
        byte[]    encoding)
        throws ioexception, pgpexception
    {
        this(new bytearrayinputstream(encoding));
    }

    /**
     * build a pgppublickeyringcollection from the passed in input stream.
     *
     * @param in  input stream containing data
     * @throws ioexception if a problem parsing the base stream occurs
     * @throws pgpexception if an object is encountered which isn't a pgppublickeyring
     */
    public pgppublickeyringcollection(
        inputstream    in)
        throws ioexception, pgpexception
    {
        pgpobjectfactory    pgpfact = new pgpobjectfactory(in);
        object              obj;

        while ((obj = pgpfact.nextobject()) != null)
        {
            if (!(obj instanceof pgppublickeyring))
            {
                throw new pgpexception(obj.getclass().getname() + " found where pgppublickeyring expected");
            }
            
            pgppublickeyring    pgppub = (pgppublickeyring)obj;
            long    key = new long(pgppub.getpublickey().getkeyid());
            
            pubrings.put(key, pgppub);
            order.add(key);
        }
    }
    
    public pgppublickeyringcollection(
        collection    collection)
        throws ioexception, pgpexception
    {
        iterator                    it = collection.iterator();
        
        while (it.hasnext())
        {
            pgppublickeyring  pgppub = (pgppublickeyring)it.next();
            
            long              key = new long(pgppub.getpublickey().getkeyid());
            
            pubrings.put(key, pgppub);
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
     * return the public key rings making up this collection.
     */
    public iterator getkeyrings()
    {
        return pubrings.values().iterator();
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
            pgppublickeyring pubring = (pgppublickeyring)it.next();
            iterator         uit = pubring.getpublickey().getuserids();

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
                        rings.add(pubring);
                    }
                }
                else
                {
                    if (next.equals(userid))
                    {
                        rings.add(pubring);
                    }
                }
            }
        }
    
        return rings.iterator();
    }

    /**
     * return the pgp public key associated with the given key id.
     * 
     * @param keyid
     * @return the pgp public key
     * @throws pgpexception
     */
    public pgppublickey getpublickey(
        long        keyid) 
        throws pgpexception
    {    
        iterator    it = this.getkeyrings();
        
        while (it.hasnext())
        {
            pgppublickeyring    pubring = (pgppublickeyring)it.next();
            pgppublickey        pub = pubring.getpublickey(keyid);
            
            if (pub != null)
            {
                return pub;
            }
        }
    
        return null;
    }
    
    /**
     * return the public key ring which contains the key referred to by keyid.
     * 
     * @param keyid key id to match against
     * @return the public key ring
     * @throws pgpexception
     */
    public pgppublickeyring getpublickeyring(
        long    keyid) 
        throws pgpexception
    {
        long    id = new long(keyid);
        
        if (pubrings.containskey(id))
        {
            return (pgppublickeyring)pubrings.get(id);
        }
        
        iterator    it = this.getkeyrings();
        
        while (it.hasnext())
        {
            pgppublickeyring    pubring = (pgppublickeyring)it.next();
            pgppublickey        pub = pubring.getpublickey(keyid);
            
            if (pub != null)
            {
                return pubring;
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
        return getpublickey(keyid) != null;
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
            pgppublickeyring    sr = (pgppublickeyring)pubrings.get(it.next());
            
            sr.encode(out);
        }
    }
    
    
    /**
     * return a new collection object containing the contents of the passed in collection and
     * the passed in public key ring.
     * 
     * @param ringcollection the collection the ring to be added to.
     * @param publickeyring the key ring to be added.
     * @return a new collection merging the current one with the passed in ring.
     * @exception illegalargumentexception if the keyid for the passed in ring is already present.
     */
    public static pgppublickeyringcollection addpublickeyring(
        pgppublickeyringcollection ringcollection,
        pgppublickeyring           publickeyring)
    {
        long        key = new long(publickeyring.getpublickey().getkeyid());
        
        if (ringcollection.pubrings.containskey(key))
        {
            throw new illegalargumentexception("collection already contains a key with a keyid for the passed in ring.");
        }
        
        map     newpubrings = new hashmap(ringcollection.pubrings);
        list    neworder = new arraylist(ringcollection.order); 
        
        newpubrings.put(key, publickeyring);
        neworder.add(key);
        
        return new pgppublickeyringcollection(newpubrings, neworder);
    }
    
    /**
     * return a new collection object containing the contents of this collection with
     * the passed in public key ring removed.
     * 
     * @param ringcollection the collection the ring to be removed from.
     * @param publickeyring the key ring to be removed.
     * @return a new collection not containing the passed in ring.
     * @exception illegalargumentexception if the keyid for the passed in ring not present.
     */
    public static pgppublickeyringcollection removepublickeyring(
        pgppublickeyringcollection ringcollection,
        pgppublickeyring           publickeyring)
    {
        long        key = new long(publickeyring.getpublickey().getkeyid());
        
        if (!ringcollection.pubrings.containskey(key))
        {
            throw new illegalargumentexception("collection does not contain a key with a keyid for the passed in ring.");
        }
        
        map     newpubrings = new hashmap(ringcollection.pubrings);
        list    neworder = new arraylist(ringcollection.order); 
        
        newpubrings.remove(key);
        
        for (int i = 0; i < neworder.size(); i++)
        {
            long    r = (long)neworder.get(i);
            
            if (r.longvalue() == key.longvalue())
            {
                neworder.remove(i);
                break;
            }
        }
        
        return new pgppublickeyringcollection(newpubrings, neworder);
    }
}
