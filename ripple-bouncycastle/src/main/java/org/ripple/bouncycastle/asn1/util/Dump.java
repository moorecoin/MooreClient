package org.ripple.bouncycastle.asn1.util;

import java.io.fileinputstream;

import org.ripple.bouncycastle.asn1.asn1inputstream;

public class dump
{
    public static void main(
        string args[])
        throws exception
    {
        fileinputstream fin = new fileinputstream(args[0]);
        asn1inputstream bin = new asn1inputstream(fin);
        object          obj = null;

        while ((obj = bin.readobject()) != null)
        {
            system.out.println(asn1dump.dumpasstring(obj));
        }
    }
}
