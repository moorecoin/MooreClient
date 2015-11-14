package org.ripple.bouncycastle.util.test;

/**
 * parsing
 */
public final class numberparsing
{
    private numberparsing() 
    {
        // hide constructor
    }
    
    public static long decodelongfromhex(string longasstring) 
    {
        if ((longasstring.charat(1) == 'x')
            || (longasstring.charat(1) == 'x'))
        {
            return long.parselong(longasstring.substring(2), 16);
        }

        return long.parselong(longasstring, 16);
    }
    
    public static int decodeintfromhex(string intasstring)
    {
        if ((intasstring.charat(1) == 'x')
            || (intasstring.charat(1) == 'x'))
        {
            return integer.parseint(intasstring.substring(2), 16);
        }

        return integer.parseint(intasstring, 16);
    }
}
