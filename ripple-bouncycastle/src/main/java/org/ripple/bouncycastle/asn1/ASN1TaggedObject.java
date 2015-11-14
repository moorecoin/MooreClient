package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

/**
 * asn.1 taggedobject - in asn.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public abstract class asn1taggedobject
    extends asn1primitive
    implements asn1taggedobjectparser
{
    int             tagno;
    boolean         empty = false;
    boolean         explicit = true;
    asn1encodable obj = null;

    static public asn1taggedobject getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        if (explicit)
        {
            return (asn1taggedobject)obj.getobject();
        }

        throw new illegalargumentexception("implicitly tagged tagged object");
    }

    static public asn1taggedobject getinstance(
        object obj) 
    {
        if (obj == null || obj instanceof asn1taggedobject) 
        {
                return (asn1taggedobject)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return asn1taggedobject.getinstance(frombytearray((byte[])obj));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("failed to construct tagged object from byte[]: " + e.getmessage());
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    /**
     * create a tagged object with the style given by the value of explicit.
     * <p>
     * if the object implements asn1choice the tag style will always be changed
     * to explicit in accordance with the asn.1 encoding rules.
     * </p>
     * @param explicit true if the object is explicitly tagged.
     * @param tagno the tag number for this object.
     * @param obj the tagged object.
     */
    public asn1taggedobject(
        boolean         explicit,
        int             tagno,
        asn1encodable   obj)
    {
        if (obj instanceof asn1choice)
        {
            this.explicit = true;
        }
        else
        {
            this.explicit = explicit;
        }
        
        this.tagno = tagno;

        if (this.explicit)
        {
            this.obj = obj;
        }
        else
        {
            asn1primitive prim = obj.toasn1primitive();

            if (prim instanceof asn1set)
            {
                asn1set s = null;
            }

            this.obj = obj;
        }
    }
    
    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof asn1taggedobject))
        {
            return false;
        }
        
        asn1taggedobject other = (asn1taggedobject)o;
        
        if (tagno != other.tagno || empty != other.empty || explicit != other.explicit)
        {
            return false;
        }
        
        if(obj == null)
        {
            if (other.obj != null)
            {
                return false;
            }
        }
        else
        {
            if (!(obj.toasn1primitive().equals(other.obj.toasn1primitive())))
            {
                return false;
            }
        }
        
        return true;
    }
    
    public int hashcode()
    {
        int code = tagno;

        // todo: actually this is wrong - the problem is that a re-encoded
        // object may end up with a different hashcode due to implicit
        // tagging. as implicit tagging is ambiguous if a sequence is involved
        // it seems the only correct method for both equals and hashcode is to
        // compare the encodings...
        if (obj != null)
        {
            code ^= obj.hashcode();
        }

        return code;
    }

    public int gettagno()
    {
        return tagno;
    }

    /**
     * return whether or not the object may be explicitly tagged. 
     * <p>
     * note: if the object has been read from an input stream, the only
     * time you can be sure if isexplicit is returning the true state of
     * affairs is if it returns false. an implicitly tagged object may appear
     * to be explicitly tagged, so you need to understand the context under
     * which the reading was done as well, see getobject below.
     */
    public boolean isexplicit()
    {
        return explicit;
    }

    public boolean isempty()
    {
        return empty;
    }

    /**
     * return whatever was following the tag.
     * <p>
     * note: tagged objects are generally context dependent if you're
     * trying to extract a tagged object you should be going via the
     * appropriate getinstance method.
     */
    public asn1primitive getobject()
    {
        if (obj != null)
        {
            return obj.toasn1primitive();
        }

        return null;
    }

    /**
     * return the object held in this tagged object as a parser assuming it has
     * the type of the passed in tag. if the object doesn't have a parser
     * associated with it, the base object is returned.
     */
    public asn1encodable getobjectparser(
        int     tag,
        boolean isexplicit)
    {
        switch (tag)
        {
        case bertags.set:
            return asn1set.getinstance(this, isexplicit).parser();
        case bertags.sequence:
            return asn1sequence.getinstance(this, isexplicit).parser();
        case bertags.octet_string:
            return asn1octetstring.getinstance(this, isexplicit).parser();
        }

        if (isexplicit)
        {
            return getobject();
        }

        throw new runtimeexception("implicit tagging not implemented for tag: " + tag);
    }

    public asn1primitive getloadedobject()
    {
        return this.toasn1primitive();
    }

    asn1primitive toderobject()
    {
        return new dertaggedobject(explicit, tagno, obj);
    }

    asn1primitive todlobject()
    {
        return new dltaggedobject(explicit, tagno, obj);
    }

    abstract void encode(asn1outputstream out)
        throws ioexception;

    public string tostring()
    {
        return "[" + tagno + "]" + obj;
    }
}
