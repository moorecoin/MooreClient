package org.ripple.bouncycastle.asn1.cms;

import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.derset;

public class attributetable
{
    private hashtable attributes = new hashtable();

    public attributetable(
        hashtable  attrs)
    {
        attributes = copytable(attrs);
    }

    public attributetable(
        asn1encodablevector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            attribute   a = attribute.getinstance(v.get(i));

            addattribute(a.getattrtype(), a);
        }
    }

    public attributetable(
        asn1set    s)
    {
        for (int i = 0; i != s.size(); i++)
        {
            attribute   a = attribute.getinstance(s.getobjectat(i));

            addattribute(a.getattrtype(), a);
        }
    }

    public attributetable(
        attribute    attr)
    {
        addattribute(attr.getattrtype(), attr);
    }

    public attributetable(
        attributes    attrs)
    {
        this(asn1set.getinstance(attrs.toasn1primitive()));
    }

    private void addattribute(
        asn1objectidentifier oid,
        attribute           a)
    {
        object value = attributes.get(oid);
        
        if (value == null)
        {
            attributes.put(oid, a);
        }
        else
        {
            vector v;
            
            if (value instanceof attribute)
            {
                v = new vector();
                
                v.addelement(value);
                v.addelement(a);
            }
            else
            {
                v = (vector)value;
            
                v.addelement(a);
            }
            
            attributes.put(oid, v);
        }
    }

    /**
     * @deprecated use asn1objectidentifier
     */
    public attribute get(derobjectidentifier oid)
    {
        return get(new asn1objectidentifier(oid.getid()));
    }

    /**
     * return the first attribute matching the object identifier oid.
     * 
     * @param oid type of attribute required.
     * @return first attribute found of type oid.
     */
    public attribute get(
        asn1objectidentifier oid)
    {
        object value = attributes.get(oid);
        
        if (value instanceof vector)
        {
            return (attribute)((vector)value).elementat(0);
        }
        
        return (attribute)value;
    }

     /**
     * @deprecated use asn1objectidentifier
     */
    public asn1encodablevector getall(derobjectidentifier oid)
    {
        return getall(new asn1objectidentifier(oid.getid()));
    }

    /**
     * return all the attributes matching the object identifier oid. the vector will be 
     * empty if there are no attributes of the required type present.
     * 
     * @param oid type of attribute required.
     * @return a vector of all the attributes found of type oid.
     */
    public asn1encodablevector getall(
        asn1objectidentifier oid)
    {
        asn1encodablevector v = new asn1encodablevector();
        
        object value = attributes.get(oid);
        
        if (value instanceof vector)
        {
            enumeration e = ((vector)value).elements();
            
            while (e.hasmoreelements())
            {
                v.add((attribute)e.nextelement());
            }
        }
        else if (value != null)
        {
            v.add((attribute)value);
        }
        
        return v;
    }

    public int size()
    {
        int size = 0;

        for (enumeration en = attributes.elements(); en.hasmoreelements();)
        {
            object o = en.nextelement();

            if (o instanceof vector)
            {
                size += ((vector)o).size();
            }
            else
            {
                size++;
            }
        }

        return size;
    }

    public hashtable tohashtable()
    {
        return copytable(attributes);
    }
    
    public asn1encodablevector toasn1encodablevector()
    {
        asn1encodablevector  v = new asn1encodablevector();
        enumeration          e = attributes.elements();
        
        while (e.hasmoreelements())
        {
            object value = e.nextelement();
            
            if (value instanceof vector)
            {
                enumeration en = ((vector)value).elements();
                
                while (en.hasmoreelements())
                {
                    v.add(attribute.getinstance(en.nextelement()));
                }
            }
            else
            {
                v.add(attribute.getinstance(value));
            }
        }
        
        return v;
    }

    public attributes toasn1structure()
    {
        return new attributes(this.toasn1encodablevector());
    }

    private hashtable copytable(
        hashtable in)
    {
        hashtable   out = new hashtable();
        enumeration e = in.keys();
        
        while (e.hasmoreelements())
        {
            object key = e.nextelement();
            
            out.put(key, in.get(key));
        }
        
        return out;
    }

    /**
     * return a new table with the passed in attribute added.
     *
     * @param attrtype
     * @param attrvalue
     * @return
     */
    public attributetable add(asn1objectidentifier attrtype, asn1encodable attrvalue)
    {
        attributetable newtable = new attributetable(attributes);

        newtable.addattribute(attrtype, new attribute(attrtype, new derset(attrvalue)));

        return newtable;
    }

    public attributetable remove(asn1objectidentifier attrtype)
    {
        attributetable newtable = new attributetable(attributes);

        newtable.attributes.remove(attrtype);

        return newtable;
    }
}
