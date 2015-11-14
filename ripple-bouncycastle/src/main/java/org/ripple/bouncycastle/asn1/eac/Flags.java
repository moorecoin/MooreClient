package org.ripple.bouncycastle.asn1.eac;

import java.util.enumeration;
import java.util.hashtable;


public class flags
{

    int value = 0;

    public flags()
    {

    }

    public flags(int v)
    {
        value = v;
    }

    public void set(int flag)
    {
        value |= flag;
    }

    public boolean isset(int flag)
    {
        return (value & flag) != 0;
    }

    public int getflags()
    {
        return value;
    }

    /* java 1.5
     string decode(map<integer, string> decodemap)
     {
         stringjoiner joiner = new stringjoiner(" ");
         for (int i : decodemap.keyset())
         {
             if (isset(i))
                 joiner.add(decodemap.get(i));
         }
         return joiner.tostring();
     }
     */

    string decode(hashtable decodemap)
    {
        stringjoiner joiner = new stringjoiner(" ");
        enumeration e = decodemap.keys();
        while (e.hasmoreelements())
        {
            integer i = (integer)e.nextelement();
            if (isset(i.intvalue()))
            {
                joiner.add((string)decodemap.get(i));
            }
        }
        return joiner.tostring();
    }

    private class stringjoiner
    {

        string mseparator;
        boolean first = true;
        stringbuffer b = new stringbuffer();

        public stringjoiner(string separator)
        {
            mseparator = separator;
        }

        public void add(string str)
        {
            if (first)
            {
                first = false;
            }
            else
            {
                b.append(mseparator);
            }

            b.append(str);
        }

        public string tostring()
        {
            return b.tostring();
        }
    }
}
