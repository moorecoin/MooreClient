package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * class representing the der-type external
 */
public class derexternal
    extends asn1primitive
{
    private asn1objectidentifier directreference;
    private asn1integer indirectreference;
    private asn1primitive datavaluedescriptor;
    private int encoding;
    private asn1primitive externalcontent;
    
    public derexternal(asn1encodablevector vector)
    {
        int offset = 0;

        asn1primitive enc = getobjfromvector(vector, offset);
        if (enc instanceof asn1objectidentifier)
        {
            directreference = (asn1objectidentifier)enc;
            offset++;
            enc = getobjfromvector(vector, offset);
        }
        if (enc instanceof asn1integer)
        {
            indirectreference = (asn1integer) enc;
            offset++;
            enc = getobjfromvector(vector, offset);
        }
        if (!(enc instanceof dertaggedobject))
        {
            datavaluedescriptor = (asn1primitive) enc;
            offset++;
            enc = getobjfromvector(vector, offset);
        }

        if (vector.size() != offset + 1)
        {
            throw new illegalargumentexception("input vector too large");
        }

        if (!(enc instanceof dertaggedobject))
        {
            throw new illegalargumentexception("no tagged object found in vector. structure doesn't seem to be of type external");
        }
        dertaggedobject obj = (dertaggedobject)enc;
        setencoding(obj.gettagno());
        externalcontent = obj.getobject();
    }

    private asn1primitive getobjfromvector(asn1encodablevector v, int index)
    {
        if (v.size() <= index)
        {
            throw new illegalargumentexception("too few objects in input vector");
        }

        return v.get(index).toasn1primitive();
    }
    /**
     * creates a new instance of derexternal
     * see x.690 for more informations about the meaning of these parameters
     * @param directreference the direct reference or <code>null</code> if not set.
     * @param indirectreference the indirect reference or <code>null</code> if not set.
     * @param datavaluedescriptor the data value descriptor or <code>null</code> if not set.
     * @param externaldata the external data in its encoded form.
     */
    public derexternal(asn1objectidentifier directreference, asn1integer indirectreference, asn1primitive datavaluedescriptor, dertaggedobject externaldata)
    {
        this(directreference, indirectreference, datavaluedescriptor, externaldata.gettagno(), externaldata.toasn1primitive());
    }

    /**
     * creates a new instance of derexternal.
     * see x.690 for more informations about the meaning of these parameters
     * @param directreference the direct reference or <code>null</code> if not set.
     * @param indirectreference the indirect reference or <code>null</code> if not set.
     * @param datavaluedescriptor the data value descriptor or <code>null</code> if not set.
     * @param encoding the encoding to be used for the external data
     * @param externaldata the external data
     */
    public derexternal(asn1objectidentifier directreference, asn1integer indirectreference, asn1primitive datavaluedescriptor, int encoding, asn1primitive externaldata)
    {
        setdirectreference(directreference);
        setindirectreference(indirectreference);
        setdatavaluedescriptor(datavaluedescriptor);
        setencoding(encoding);
        setexternalcontent(externaldata.toasn1primitive());
    }

    /* (non-javadoc)
     * @see java.lang.object#hashcode()
     */
    public int hashcode()
    {
        int ret = 0;
        if (directreference != null)
        {
            ret = directreference.hashcode();
        }
        if (indirectreference != null)
        {
            ret ^= indirectreference.hashcode();
        }
        if (datavaluedescriptor != null)
        {
            ret ^= datavaluedescriptor.hashcode();
        }
        ret ^= externalcontent.hashcode();
        return ret;
    }

    boolean isconstructed()
    {
        return true;
    }

    int encodedlength()
        throws ioexception
    {
        return this.getencoded().length;
    }

    /* (non-javadoc)
     * @see org.bouncycastle.asn1.asn1primitive#encode(org.bouncycastle.asn1.deroutputstream)
     */
    void encode(asn1outputstream out)
        throws ioexception
    {
        bytearrayoutputstream baos = new bytearrayoutputstream();
        if (directreference != null)
        {
            baos.write(directreference.getencoded(asn1encoding.der));
        }
        if (indirectreference != null)
        {
            baos.write(indirectreference.getencoded(asn1encoding.der));
        }
        if (datavaluedescriptor != null)
        {
            baos.write(datavaluedescriptor.getencoded(asn1encoding.der));
        }
        dertaggedobject obj = new dertaggedobject(true, encoding, externalcontent);
        baos.write(obj.getencoded(asn1encoding.der));
        out.writeencoded(bertags.constructed, bertags.external, baos.tobytearray());
    }

    /* (non-javadoc)
     * @see org.bouncycastle.asn1.asn1primitive#asn1equals(org.bouncycastle.asn1.asn1primitive)
     */
    boolean asn1equals(asn1primitive o)
    {
        if (!(o instanceof derexternal))
        {
            return false;
        }
        if (this == o)
        {
            return true;
        }
        derexternal other = (derexternal)o;
        if (directreference != null)
        {
            if (other.directreference == null || !other.directreference.equals(directreference))  
            {
                return false;
            }
        }
        if (indirectreference != null)
        {
            if (other.indirectreference == null || !other.indirectreference.equals(indirectreference))
            {
                return false;
            }
        }
        if (datavaluedescriptor != null)
        {
            if (other.datavaluedescriptor == null || !other.datavaluedescriptor.equals(datavaluedescriptor))
            {
                return false;
            }
        }
        return externalcontent.equals(other.externalcontent);
    }

    /**
     * returns the data value descriptor
     * @return the descriptor
     */
    public asn1primitive getdatavaluedescriptor()
    {
        return datavaluedescriptor;
    }

    /**
     * returns the direct reference of the external element
     * @return the reference
     */
    public asn1objectidentifier getdirectreference()
    {
        return directreference;
    }

    /**
     * returns the encoding of the content. valid values are
     * <ul>
     * <li><code>0</code> single-asn1-type</li>
     * <li><code>1</code> octet string</li>
     * <li><code>2</code> bit string</li>
     * </ul>
     * @return the encoding
     */
    public int getencoding()
    {
        return encoding;
    }
    
    /**
     * returns the content of this element
     * @return the content
     */
    public asn1primitive getexternalcontent()
    {
        return externalcontent;
    }
    
    /**
     * returns the indirect reference of this element
     * @return the reference
     */
    public asn1integer getindirectreference()
    {
        return indirectreference;
    }
    
    /**
     * sets the data value descriptor
     * @param datavaluedescriptor the descriptor
     */
    private void setdatavaluedescriptor(asn1primitive datavaluedescriptor)
    {
        this.datavaluedescriptor = datavaluedescriptor;
    }

    /**
     * sets the direct reference of the external element
     * @param directreferemce the reference
     */
    private void setdirectreference(asn1objectidentifier directreferemce)
    {
        this.directreference = directreferemce;
    }
    
    /**
     * sets the encoding of the content. valid values are
     * <ul>
     * <li><code>0</code> single-asn1-type</li>
     * <li><code>1</code> octet string</li>
     * <li><code>2</code> bit string</li>
     * </ul>
     * @param encoding the encoding
     */
    private void setencoding(int encoding)
    {
        if (encoding < 0 || encoding > 2)
        {
            throw new illegalargumentexception("invalid encoding value: " + encoding);
        }
        this.encoding = encoding;
    }
    
    /**
     * sets the content of this element
     * @param externalcontent the content
     */
    private void setexternalcontent(asn1primitive externalcontent)
    {
        this.externalcontent = externalcontent;
    }
    
    /**
     * sets the indirect reference of this element
     * @param indirectreference the reference
     */
    private void setindirectreference(asn1integer indirectreference)
    {
        this.indirectreference = indirectreference;
    }
}
