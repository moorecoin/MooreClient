package org.ripple.bouncycastle.util;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.util.vector;

public final class strings
{
    public static string fromutf8bytearray(byte[] bytes)
    {
        int i = 0;
        int length = 0;

        while (i < bytes.length)
        {
            length++;
            if ((bytes[i] & 0xf0) == 0xf0)
            {
                // surrogate pair
                length++;
                i += 4;
            }
            else if ((bytes[i] & 0xe0) == 0xe0)
            {
                i += 3;
            }
            else if ((bytes[i] & 0xc0) == 0xc0)
            {
                i += 2;
            }
            else
            {
                i += 1;
            }
        }

        char[] cs = new char[length];

        i = 0;
        length = 0;

        while (i < bytes.length)
        {
            char ch;

            if ((bytes[i] & 0xf0) == 0xf0)
            {
                int codepoint = ((bytes[i] & 0x03) << 18) | ((bytes[i+1] & 0x3f) << 12) | ((bytes[i+2] & 0x3f) << 6) | (bytes[i+3] & 0x3f);
                int u = codepoint - 0x10000;
                char w1 = (char)(0xd800 | (u >> 10));
                char w2 = (char)(0xdc00 | (u & 0x3ff));
                cs[length++] = w1;
                ch = w2;
                i += 4;
            }
            else if ((bytes[i] & 0xe0) == 0xe0)
            {
                ch = (char)(((bytes[i] & 0x0f) << 12)
                        | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f));
                i += 3;
            }
            else if ((bytes[i] & 0xd0) == 0xd0)
            {
                ch = (char)(((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
                i += 2;
            }
            else if ((bytes[i] & 0xc0) == 0xc0)
            {
                ch = (char)(((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
                i += 2;
            }
            else
            {
                ch = (char)(bytes[i] & 0xff);
                i += 1;
            }

            cs[length++] = ch;
        }

        return new string(cs);
    }
    
    public static byte[] toutf8bytearray(string string)
    {
        return toutf8bytearray(string.tochararray());
    }

    public static byte[] toutf8bytearray(char[] string)
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();

        try
        {
            toutf8bytearray(string, bout);
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("cannot encode string to byte array!");
        }
        
        return bout.tobytearray();
    }

    public static void toutf8bytearray(char[] string, outputstream sout)
        throws ioexception
    {
        char[] c = string;
        int i = 0;

        while (i < c.length)
        {
            char ch = c[i];

            if (ch < 0x0080)
            {
                sout.write(ch);
            }
            else if (ch < 0x0800)
            {
                sout.write(0xc0 | (ch >> 6));
                sout.write(0x80 | (ch & 0x3f));
            }
            // surrogate pair
            else if (ch >= 0xd800 && ch <= 0xdfff)
            {
                // in error - can only happen, if the java string class has a
                // bug.
                if (i + 1 >= c.length)
                {
                    throw new illegalstateexception("invalid utf-16 codepoint");
                }
                char w1 = ch;
                ch = c[++i];
                char w2 = ch;
                // in error - can only happen, if the java string class has a
                // bug.
                if (w1 > 0xdbff)
                {
                    throw new illegalstateexception("invalid utf-16 codepoint");
                }
                int codepoint = (((w1 & 0x03ff) << 10) | (w2 & 0x03ff)) + 0x10000;
                sout.write(0xf0 | (codepoint >> 18));
                sout.write(0x80 | ((codepoint >> 12) & 0x3f));
                sout.write(0x80 | ((codepoint >> 6) & 0x3f));
                sout.write(0x80 | (codepoint & 0x3f));
            }
            else
            {
                sout.write(0xe0 | (ch >> 12));
                sout.write(0x80 | ((ch >> 6) & 0x3f));
                sout.write(0x80 | (ch & 0x3f));
            }

            i++;
        }
    }

    /**
     * a locale independent version of touppercase.
     * 
     * @param string input to be converted
     * @return a us ascii uppercase version
     */
    public static string touppercase(string string)
    {
        boolean changed = false;
        char[] chars = string.tochararray();
        
        for (int i = 0; i != chars.length; i++)
        {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch)
            {
                changed = true;
                chars[i] = (char)(ch - 'a' + 'a');
            }
        }
        
        if (changed)
        {
            return new string(chars);
        }
        
        return string;
    }
    
    /**
     * a locale independent version of tolowercase.
     * 
     * @param string input to be converted
     * @return a us ascii lowercase version
     */
    public static string tolowercase(string string)
    {
        boolean changed = false;
        char[] chars = string.tochararray();
        
        for (int i = 0; i != chars.length; i++)
        {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch)
            {
                changed = true;
                chars[i] = (char)(ch - 'a' + 'a');
            }
        }
        
        if (changed)
        {
            return new string(chars);
        }
        
        return string;
    }

    public static byte[] tobytearray(char[] chars)
    {
        byte[] bytes = new byte[chars.length];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

    public static byte[] tobytearray(string string)
    {
        byte[] bytes = new byte[string.length()];

        for (int i = 0; i != bytes.length; i++)
        {
            char ch = string.charat(i);

            bytes[i] = (byte)ch;
        }

        return bytes;
    }

    /**
     * convert an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting string.
     */
    public static string frombytearray(byte[] bytes)
    {
        return new string(aschararray(bytes));
    }

    /**
     * do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting string.
     */
    public static char[] aschararray(byte[] bytes)
    {
        char[] chars = new char[bytes.length];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }

        return chars;
    }

    public static string[] split(string input, char delimiter)
    {
        vector           v = new vector();
        boolean moretokens = true;
        string substring;

        while (moretokens)
        {
            int tokenlocation = input.indexof(delimiter);
            if (tokenlocation > 0)
            {
                substring = input.substring(0, tokenlocation);
                v.addelement(substring);
                input = input.substring(tokenlocation + 1);
            }
            else
            {
                moretokens = false;
                v.addelement(input);
            }
        }

        string[] res = new string[v.size()];

        for (int i = 0; i != res.length; i++)
        {
            res[i] = (string)v.elementat(i);
        }
        return res;
    }
}
