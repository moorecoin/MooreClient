package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;
import java.util.vector;

public abstract class asn1sequence
    extends asn1primitive
{
    protected vector seq = new vector();

    /**
     * return an asn1sequence from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1sequence getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1sequence)
        {
            return (asn1sequence)obj;
        }
        else if (obj instanceof asn1sequenceparser)
        {
            return asn1sequence.getinstance(((asn1sequenceparser)obj).toasn1primitive());
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return asn1sequence.getinstance(frombytearray((byte[])obj));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("failed to construct sequence from byte[]: " + e.getmessage());
            }
        }
        else if (obj instanceof asn1encodable)
        {
            asn1primitive primitive = ((asn1encodable)obj).toasn1primitive();

            if (primitive instanceof asn1sequence)
            {
                return (asn1sequence)primitive;
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an asn1 sequence from a tagged object. there is a special
     * case here, if an object appears to have been explicitly tagged on 
     * reading but we were expecting it to be implicitly tagged in the 
     * normal course of events it indicates that we lost the surrounding
     * sequence - so we need to add it back (this will happen if the tagged
     * object is a sequence that contains other sequences). if you are
     * dealing with implicitly tagged sequences you really <b>should</b>
     * be using this method.
     *
     * @param obj the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged,
     *          false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *          be converted.
     */
    public static asn1sequence getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        if (explicit)
        {
            if (!obj.isexplicit())
            {
                throw new illegalargumentexception("object implicit - explicit expected.");
            }

            return asn1sequence.getinstance(obj.getobject().toasn1primitive());
        }
        else
        {
            //
            // constructed object which appears to be explicitly tagged
            // when it should be implicit means we have to add the
            // surrounding sequence.
            //
            if (obj.isexplicit())
            {
                if (obj instanceof bertaggedobject)
                {
                    return new bersequence(obj.getobject());
                }
                else
                {
                    return new dlsequence(obj.getobject());
                }
            }
            else
            {
                if (obj.getobject() instanceof asn1sequence)
                {
                    return (asn1sequence)obj.getobject();
                }
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    /**
     * create an empty sequence
     */
    protected asn1sequence()
    {
    }

    /**
     * create a sequence containing one object
     */
    protected asn1sequence(
        asn1encodable obj)
    {
        seq.addelement(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    protected asn1sequence(
        asn1encodablevector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            seq.addelement(v.get(i));
        }
    }

    /**
     * create a sequence containing a vector of objects.
     */
    protected asn1sequence(
        asn1encodable[]   array)
    {
        for (int i = 0; i != array.length; i++)
        {
            seq.addelement(array[i]);
        }
    }

    public asn1encodable[] toarray()
    {
        asn1encodable[] values = new asn1encodable[this.size()];

        for (int i = 0; i != this.size(); i++)
        {
            values[i] = this.getobjectat(i);
        }

        return values;
    }

    public enumeration getobjects()
    {
        return seq.elements();
    }

    public asn1sequenceparser parser()
    {
        final asn1sequence outer = this;

        return new asn1sequenceparser()
        {
            private final int max = size();

            private int index;

            public asn1encodable readobject() throws ioexception
            {
                if (index == max)
                {
                    return null;
                }
                
                asn1encodable obj = getobjectat(index++);
                if (obj instanceof asn1sequence)
                {
                    return ((asn1sequence)obj).parser();
                }
                if (obj instanceof asn1set)
                {
                    return ((asn1set)obj).parser();
                }

                return obj;
            }

            public asn1primitive getloadedobject()
            {
                return outer;
            }
            
            public asn1primitive toasn1primitive()
            {
                return outer;
            }
        };
    }

    /**
     * return the object at the sequence position indicated by index.
     *
     * @param index the sequence number (starting at zero) of the object
     * @return the object at the sequence position indicated by index.
     */
    public asn1encodable getobjectat(
        int index)
    {
        return (asn1encodable)seq.elementat(index);
    }

    /**
     * return the number of objects in this sequence.
     *
     * @return the number of objects in this sequence.
     */
    public int size()
    {
        return seq.size();
    }

    public int hashcode()
    {
        enumeration             e = this.getobjects();
        int                     hashcode = size();

        while (e.hasmoreelements())
        {
            object o = getnext(e);
            hashcode *= 17;

            hashcode ^= o.hashcode();
        }

        return hashcode;
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof asn1sequence))
        {
            return false;
        }
        
        asn1sequence   other = (asn1sequence)o;

        if (this.size() != other.size())
        {
            return false;
        }

        enumeration s1 = this.getobjects();
        enumeration s2 = other.getobjects();

        while (s1.hasmoreelements())
        {
            asn1encodable obj1 = getnext(s1);
            asn1encodable obj2 = getnext(s2);

            asn1primitive o1 = obj1.toasn1primitive();
            asn1primitive o2 = obj2.toasn1primitive();

            if (o1 == o2 || o1.equals(o2))
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private asn1encodable getnext(enumeration e)
    {
        asn1encodable encobj = (asn1encodable)e.nextelement();

        return encobj;
    }

    asn1primitive toderobject()
    {
        asn1sequence derseq = new dersequence();

        derseq.seq = this.seq;

        return derseq;
    }

    asn1primitive todlobject()
    {
        asn1sequence dlseq = new dlsequence();

        dlseq.seq = this.seq;

        return dlseq;
    }

    boolean isconstructed()
    {
        return true;
    }

    abstract void encode(asn1outputstream out)
        throws ioexception;

    public string tostring() 
    {
        return seq.tostring();
    }
}
