package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.outputstream;

public class bersequencegenerator
    extends bergenerator
{
    public bersequencegenerator(
        outputstream out) 
        throws ioexception
    {
        super(out);

        writeberheader(bertags.constructed | bertags.sequence);
    }

    public bersequencegenerator(
        outputstream out,
        int tagno,
        boolean isexplicit) 
        throws ioexception
    {
        super(out, tagno, isexplicit);
        
        writeberheader(bertags.constructed | bertags.sequence);
    }

    public void addobject(
        asn1encodable object)
        throws ioexception
    {
        object.toasn1primitive().encode(new beroutputstream(_out));
    }
    
    public void close() 
        throws ioexception
    {
        writeberend();
    }
}
