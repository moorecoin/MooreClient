package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.enumeration;
import java.util.vector;

abstract public class asn1set
    extends asn1primitive
{
    private vector set = new vector();
    private boolean issorted = false;

    /**
     * return an asn1set from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1set getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1set)
        {
            return (asn1set)obj;
        }
        else if (obj instanceof asn1setparser)
        {
            return asn1set.getinstance(((asn1setparser)obj).toasn1primitive());
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return asn1set.getinstance(asn1primitive.frombytearray((byte[])obj));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("failed to construct set from byte[]: " + e.getmessage());
            }
        }
        else if (obj instanceof asn1encodable)
        {
            asn1primitive primitive = ((asn1encodable)obj).toasn1primitive();

            if (primitive instanceof asn1set)
            {
                return (asn1set)primitive;
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an asn1 set from a tagged object. there is a special
     * case here, if an object appears to have been explicitly tagged on 
     * reading but we were expecting it to be implicitly tagged in the 
     * normal course of events it indicates that we lost the surrounding
     * set - so we need to add it back (this will happen if the tagged
     * object is a sequence that contains other sequences). if you are
     * dealing with implicitly tagged sets you really <b>should</b>
     * be using this method.
     *
     * @param obj the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged
     *          false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *          be converted.
     */
    public static asn1set getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        if (explicit)
        {
            if (!obj.isexplicit())
            {
                throw new illegalargumentexception("object implicit - explicit expected.");
            }

            return (asn1set)obj.getobject();
        }
        else
        {
            //
            // constructed object which appears to be explicitly tagged
            // and it's really implicit means we have to add the
            // surrounding set.
            //
            if (obj.isexplicit())
            {
                if (obj instanceof bertaggedobject)
                {
                    return new berset(obj.getobject());
                }
                else
                {
                    return new dlset(obj.getobject());
                }
            }
            else
            {
                if (obj.getobject() instanceof asn1set)
                {
                    return (asn1set)obj.getobject();
                }

                //
                // in this case the parser returns a sequence, convert it
                // into a set.
                //
                if (obj.getobject() instanceof asn1sequence)
                {
                    asn1sequence s = (asn1sequence)obj.getobject();

                    if (obj instanceof bertaggedobject)
                    {
                        return new berset(s.toarray());
                    }
                    else
                    {
                        return new dlset(s.toarray());
                    }
                }
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    protected asn1set()
    {
    }

    /**
     * create a sequence containing one object
     */
    protected asn1set(
        asn1encodable obj)
    {
        set.addelement(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    protected asn1set(
        asn1encodablevector v,
        boolean                  dosort)
    {
        for (int i = 0; i != v.size(); i++)
        {
            set.addelement(v.get(i));
        }

        if (dosort)
        {
            this.sort();
        }
    }

    /**
     * create a sequence containing a vector of objects.
     */
    protected asn1set(
        asn1encodable[]   array,
        boolean dosort)
    {
        for (int i = 0; i != array.length; i++)
        {
            set.addelement(array[i]);
        }

        if (dosort)
        {
            this.sort();
        }
    }

    public enumeration getobjects()
    {
        return set.elements();
    }

    /**
     * return the object at the set position indicated by index.
     *
     * @param index the set number (starting at zero) of the object
     * @return the object at the set position indicated by index.
     */
    public asn1encodable getobjectat(
        int index)
    {
        return (asn1encodable)set.elementat(index);
    }

    /**
     * return the number of objects in this set.
     *
     * @return the number of objects in this set.
     */
    public int size()
    {
        return set.size();
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

    public asn1setparser parser()
    {
        final asn1set outer = this;

        return new asn1setparser()
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

    asn1primitive toderobject()
    {
        if (issorted)
        {
            asn1set derset = new derset();

            derset.set = this.set;

            return derset;
        }
        else
        {
            vector v = new vector();

            for (int i = 0; i != set.size(); i++)
            {
                v.addelement(set.elementat(i));
            }

            asn1set derset = new derset();

            derset.set = v;

            derset.sort();

            return derset;
        }
    }

    asn1primitive todlobject()
    {
        asn1set derset = new dlset();

        derset.set = this.set;

        return derset;
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof asn1set))
        {
            return false;
        }

        asn1set   other = (asn1set)o;

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

        // unfortunately null was allowed as a substitute for der null
        if (encobj == null)
        {
            return dernull.instance;
        }

        return encobj;
    }

    /**
     * return true if a <= b (arrays are assumed padded with zeros).
     */
    private boolean lessthanorequal(
         byte[] a,
         byte[] b)
    {
        int len = math.min(a.length, b.length);
        for (int i = 0; i != len; ++i)
        {
            if (a[i] != b[i])
            {
                return (a[i] & 0xff) < (b[i] & 0xff);
            }
        }
        return len == a.length;
    }

    private byte[] getencoded(
        asn1encodable obj)
    {
        bytearrayoutputstream   bout = new bytearrayoutputstream();
        asn1outputstream        aout = new asn1outputstream(bout);

        try
        {
            aout.writeobject(obj);
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("cannot encode object added to set");
        }

        return bout.tobytearray();
    }

    protected void sort()
    {
        if (!issorted)
        {
            issorted = true;
            if (set.size() > 1)
            {
                boolean    swapped = true;
                int        lastswap = set.size() - 1;

                while (swapped)
                {
                    int    index = 0;
                    int    swapindex = 0;
                    byte[] a = getencoded((asn1encodable)set.elementat(0));

                    swapped = false;

                    while (index != lastswap)
                    {
                        byte[] b = getencoded((asn1encodable)set.elementat(index + 1));

                        if (lessthanorequal(a, b))
                        {
                            a = b;
                        }
                        else
                        {
                            object  o = set.elementat(index);

                            set.setelementat(set.elementat(index + 1), index);
                            set.setelementat(o, index + 1);

                            swapped = true;
                            swapindex = index;
                        }

                        index++;
                    }

                    lastswap = swapindex;
                }
            }
        }
    }

    boolean isconstructed()
    {
        return true;
    }

    abstract void encode(asn1outputstream out)
            throws ioexception;

    public string tostring() 
    {
        return set.tostring();
    }
}
