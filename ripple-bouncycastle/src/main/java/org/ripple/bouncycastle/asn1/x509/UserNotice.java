package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <code>usernotice</code> class, used in
 * <code>certificatepolicies</code> x509 extensions (in policy
 * qualifiers).
 * <pre>
 * usernotice ::= sequence {
 *      noticeref        noticereference optional,
 *      explicittext     displaytext optional}
 *
 * </pre>
 * 
 * @see policyqualifierid
 * @see policyinformation
 */
public class usernotice 
    extends asn1object
{
    private noticereference noticeref;
    private displaytext     explicittext;
   
    /**
     * creates a new <code>usernotice</code> instance.
     *
     * @param noticeref a <code>noticereference</code> value
     * @param explicittext a <code>displaytext</code> value
     */
    public usernotice(
        noticereference noticeref, 
        displaytext explicittext) 
    {
        this.noticeref = noticeref;
        this.explicittext = explicittext;
    }

    /**
     * creates a new <code>usernotice</code> instance.
     *
     * @param noticeref a <code>noticereference</code> value
     * @param str the explicittext field as a string. 
     */
    public usernotice(
        noticereference noticeref, 
        string str) 
    {
        this(noticeref, new displaytext(str));
    }

    /**
     * creates a new <code>usernotice</code> instance.
     * <p>useful from reconstructing a <code>usernotice</code> instance
     * from its encodable/encoded form. 
     *
     * @param as an <code>asn1sequence</code> value obtained from either
     * calling @{link toasn1primitive()} for a <code>usernotice</code>
     * instance or from parsing it from a der-encoded stream. 
     */
    private usernotice(
       asn1sequence as) 
    {
       if (as.size() == 2)
       {
           noticeref = noticereference.getinstance(as.getobjectat(0));
           explicittext = displaytext.getinstance(as.getobjectat(1));
       }
       else if (as.size() == 1)
       {
           if (as.getobjectat(0).toasn1primitive() instanceof asn1sequence)
           {
               noticeref = noticereference.getinstance(as.getobjectat(0));
           }
           else
           {
               explicittext = displaytext.getinstance(as.getobjectat(0));
           }
       }
       else
       {
           throw new illegalargumentexception("bad sequence size: " + as.size());
       }
    }

    public static usernotice getinstance(
        object obj)
    {
        if (obj instanceof usernotice)
        {
            return (usernotice)obj;
        }

        if (obj != null)
        {
            return new usernotice(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public noticereference getnoticeref()
    {
        return noticeref;
    }
    
    public displaytext getexplicittext()
    {
        return explicittext;
    }
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector av = new asn1encodablevector();
      
        if (noticeref != null)
        {
            av.add(noticeref);
        }
        
        if (explicittext != null)
        {
            av.add(explicittext);
        }
         
        return new dersequence(av);
    }
}
