package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * implementation of the rolesyntax object as specified by the rfc3281.
 * 
 * <pre>
 * rolesyntax ::= sequence {
 *                 roleauthority  [0] generalnames optional,
 *                 rolename       [1] generalname
 *           } 
 * </pre>
 */
public class rolesyntax 
    extends asn1object
{
    private generalnames roleauthority;
    private generalname rolename;

    /**
     * rolesyntax factory method.
     * @param obj the object used to construct an instance of <code>
     * rolesyntax</code>. it must be an instance of <code>rolesyntax
     * </code> or <code>asn1sequence</code>.
     * @return the instance of <code>rolesyntax</code> built from the
     * supplied object.
     * @throws java.lang.illegalargumentexception if the object passed
     * to the factory is not an instance of <code>rolesyntax</code> or
     * <code>asn1sequence</code>.
     */
    public static rolesyntax getinstance(
        object obj)
    {
        
        if (obj instanceof rolesyntax)
        {
            return (rolesyntax)obj;
        }
        else if (obj != null)
        {
            return new rolesyntax(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    /**
     * constructor.
     * @param roleauthority the role authority of this rolesyntax.
     * @param rolename    the role name of this rolesyntax.
     */
    public rolesyntax(
        generalnames roleauthority,
        generalname rolename)
    {
        if(rolename == null || 
                rolename.gettagno() != generalname.uniformresourceidentifier ||
                ((asn1string)rolename.getname()).getstring().equals(""))
        {
            throw new illegalargumentexception("the role name must be non empty and must " +
                    "use the uri option of generalname");
        }
        this.roleauthority = roleauthority;
        this.rolename = rolename;
    }
    
    /**
     * constructor. invoking this constructor is the same as invoking
     * <code>new rolesyntax(null, rolename)</code>.
     * @param rolename    the role name of this rolesyntax.
     */
    public rolesyntax(
        generalname rolename)
    {
        this(null, rolename);
    }

    /**
     * utility constructor. takes a <code>string</code> argument representing
     * the role name, builds a <code>generalname</code> to hold the role name
     * and calls the constructor that takes a <code>generalname</code>.
     * @param rolename
     */
    public rolesyntax(
        string rolename)
    {
        this(new generalname(generalname.uniformresourceidentifier,
                (rolename == null)? "": rolename));
    }
    
    /**
     * constructor that builds an instance of <code>rolesyntax</code> by
     * extracting the encoded elements from the <code>asn1sequence</code>
     * object supplied.
     * @param seq    an instance of <code>asn1sequence</code> that holds
     * the encoded elements used to build this <code>rolesyntax</code>.
     */
    private rolesyntax(
        asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        for (int i = 0; i != seq.size(); i++)
        {
            asn1taggedobject taggedobject = asn1taggedobject.getinstance(seq.getobjectat(i));
            switch (taggedobject.gettagno())
            {
            case 0:
                roleauthority = generalnames.getinstance(taggedobject, false);
                break;
            case 1:
                rolename = generalname.getinstance(taggedobject, true);
                break;
            default:
                throw new illegalargumentexception("unknown tag in rolesyntax");
            }
        }
    }

    /**
     * gets the role authority of this rolesyntax.
     * @return    an instance of <code>generalnames</code> holding the
     * role authority of this rolesyntax.
     */
    public generalnames getroleauthority()
    {
        return this.roleauthority;
    }
    
    /**
     * gets the role name of this rolesyntax.
     * @return    an instance of <code>generalname</code> holding the
     * role name of this rolesyntax.
     */
    public generalname getrolename()
    {
        return this.rolename;
    }
    
    /**
     * gets the role name as a <code>java.lang.string</code> object.
     * @return    the role name of this rolesyntax represented as a 
     * <code>java.lang.string</code> object.
     */
    public string getrolenameasstring()
    {
        asn1string str = (asn1string)this.rolename.getname();
        
        return str.getstring();
    }
    
    /**
     * gets the role authority as a <code>string[]</code> object.
     * @return the role authority of this rolesyntax represented as a
     * <code>string[]</code> array.
     */
    public string[] getroleauthorityasstring() 
    {
        if(roleauthority == null) 
        {
            return new string[0];
        }
        
        generalname[] names = roleauthority.getnames();
        string[] namesstring = new string[names.length];
        for(int i = 0; i < names.length; i++) 
        {
            asn1encodable value = names[i].getname();
            if(value instanceof asn1string)
            {
                namesstring[i] = ((asn1string)value).getstring();
            }
            else
            {
                namesstring[i] = value.tostring();
            }
        }
        return namesstring;
    }
    
    /**
     * implementation of the method <code>toasn1object</code> as
     * required by the superclass <code>asn1encodable</code>.
     * 
     * <pre>
     * rolesyntax ::= sequence {
     *                 roleauthority  [0] generalnames optional,
     *                 rolename       [1] generalname
     *           } 
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        if(this.roleauthority != null)
        {
            v.add(new dertaggedobject(false, 0, roleauthority));
        }
        v.add(new dertaggedobject(true, 1, rolename));
        
        return new dersequence(v);
    }
    
    public string tostring() 
    {
        stringbuffer buff = new stringbuffer("name: " + this.getrolenameasstring() +
                " - auth: ");
        if(this.roleauthority == null || roleauthority.getnames().length == 0)
        {
            buff.append("n/a");
        }
        else 
        {
            string[] names = this.getroleauthorityasstring();
            buff.append('[').append(names[0]);
            for(int i = 1; i < names.length; i++) 
            {
                    buff.append(", ").append(names[i]);
            }
            buff.append(']');
        }
        return buff.tostring();
    }
}
