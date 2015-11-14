package org.ripple.bouncycastle.asn1.util;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1primitive;

/**
 * @deprecated use asn1dump.
 */
public class derdump
    extends asn1dump
{
    /**
     * dump out a der object as a formatted string
     *
     * @param obj the asn1primitive to be dumped out.
     */
    public static string dumpasstring(
        asn1primitive obj)
    {
        stringbuffer buf = new stringbuffer();

        _dumpasstring("", false, obj, buf);

        return buf.tostring();
    }

    /**
     * dump out a der object as a formatted string
     *
     * @param obj the asn1primitive to be dumped out.
     */
    public static string dumpasstring(
        asn1encodable obj)
    {
        stringbuffer buf = new stringbuffer();

        _dumpasstring("", false, obj.toasn1primitive(), buf);

        return buf.tostring();
    }
}
