
package org.ripple.bouncycastle.i18n.filter;

/**
 * html filter
 */
public class htmlfilter implements filter 
{

    public string dofilter(string input) 
    {
        stringbuffer buf = new stringbuffer(input);
        int i = 0;
        while (i < buf.length()) 
        {
            char ch = buf.charat(i);
            switch (ch)
            {
            case '<':
                buf.replace(i,i+1,"&#60");
                break;
            case '>':
                buf.replace(i,i+1,"&#62");
                break;
            case '(':
                buf.replace(i,i+1,"&#40");
                break;
            case ')':
                buf.replace(i,i+1,"&#41");
                break;
            case '#':
                buf.replace(i,i+1,"&#35");
                break;
            case '&':
                buf.replace(i,i+1,"&#38");
                break;
            case '\"':
                buf.replace(i,i+1,"&#34");
                break;
            case '\'':
                buf.replace(i,i+1,"&#39");
                break;
            case '%':
                buf.replace(i,i+1,"&#37");
                break;
            case ';':
                buf.replace(i,i+1,"&#59");
                break;
            case '+':
                buf.replace(i,i+1,"&#43");
                break;
            case '-':
                buf.replace(i,i+1,"&#45");
                break;
            default:
                i -= 3;
            }
            i += 4;
        }
        return buf.tostring();
    }
    
    public string dofilterurl(string input)
    {
        return dofilter(input);
    }

}
