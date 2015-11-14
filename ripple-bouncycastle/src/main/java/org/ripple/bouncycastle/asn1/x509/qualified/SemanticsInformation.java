package org.ripple.bouncycastle.asn1.x509.qualified;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.generalname;

/**
 * the semanticsinformation object.
 * <pre>
 *       semanticsinformation ::= sequence {
 *         semanticsidentifier        object identifier   optional,
 *         nameregistrationauthorities nameregistrationauthorities
 *                                                         optional }
 *         (with components {..., semanticsidentifier present}|
 *          with components {..., nameregistrationauthorities present})
 *
 *     nameregistrationauthorities ::=  sequence size (1..max) of
 *         generalname
 * </pre>
 */
public class semanticsinformation
    extends asn1object
{
    private asn1objectidentifier semanticsidentifier;
    private generalname[] nameregistrationauthorities;
    
    public static semanticsinformation getinstance(object obj)
    {
        if (obj instanceof semanticsinformation)
        {
            return (semanticsinformation)obj;
        }

        if (obj != null)
        {
            return new semanticsinformation(asn1sequence.getinstance(obj));            
        }
        
        return null;
    }
        
    private semanticsinformation(asn1sequence seq)
    {
        enumeration e = seq.getobjects();
        if (seq.size() < 1)
        {
             throw new illegalargumentexception("no objects in semanticsinformation");
        }
        
        object object = e.nextelement();
        if (object instanceof asn1objectidentifier)
        {
            semanticsidentifier = asn1objectidentifier.getinstance(object);
            if (e.hasmoreelements())
            {
                object = e.nextelement();
            }
            else
            {
                object = null;
            }
        }
        
        if (object != null)
        {
            asn1sequence generalnameseq = asn1sequence.getinstance(object);
            nameregistrationauthorities = new generalname[generalnameseq.size()];
            for (int i= 0; i < generalnameseq.size(); i++)
            {
                nameregistrationauthorities[i] = generalname.getinstance(generalnameseq.getobjectat(i));
            } 
        }
    }
        
    public semanticsinformation(
        asn1objectidentifier semanticsidentifier,
        generalname[] generalnames)
    {
        this.semanticsidentifier = semanticsidentifier;
        this.nameregistrationauthorities = generalnames;
    }

    public semanticsinformation(asn1objectidentifier semanticsidentifier)
    {
        this.semanticsidentifier = semanticsidentifier;
        this.nameregistrationauthorities = null;
    }

    public semanticsinformation(generalname[] generalnames)
    {
        this.semanticsidentifier = null;
        this.nameregistrationauthorities = generalnames;
    }        
    
    public asn1objectidentifier getsemanticsidentifier()
    {
        return semanticsidentifier;
    }
        
    public generalname[] getnameregistrationauthorities()
    {
        return nameregistrationauthorities;
    } 
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        
        if (this.semanticsidentifier != null)
        {
            seq.add(semanticsidentifier);
        }
        if (this.nameregistrationauthorities != null)
        {
            asn1encodablevector seqname = new asn1encodablevector();
            for (int i = 0; i < nameregistrationauthorities.length; i++) 
            {
                seqname.add(nameregistrationauthorities[i]);
            }            
            seq.add(new dersequence(seqname));
        }            
        
        return new dersequence(seq);
    }                   
}
