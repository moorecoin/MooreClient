
package org.ripple.bouncycastle.i18n.filter;

/**
 * filter for strings to store in a sql table.
 * 
 * escapes ' " = - / \ ; \r \n
 */
public class sqlfilter implements filter
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
            case '\'':
                buf.replace(i,i+1,"\\\'");
                i += 1;
                break;
            case '\"':
                buf.replace(i,i+1,"\\\"");
                i += 1;
                break;
            case '=':
                buf.replace(i,i+1,"\\=");
                i += 1;
                break;
            case '-':
                buf.replace(i,i+1,"\\-");
                i += 1;
                break;
            case '/':
                buf.replace(i,i+1,"\\/");
                i += 1;
                break;
            case '\\':
                buf.replace(i,i+1,"\\\\");
                i += 1;
                break;
            case ';':
                buf.replace(i,i+1,"\\;");
                i += 1;
                break;
            case '\r':
                buf.replace(i,i+1,"\\r");
                i += 1;
                break;
            case '\n':
                buf.replace(i,i+1,"\\n");
                i += 1;
                break;
            default:
            }
            i++;
        }
        return buf.tostring();
    }
    
    public string dofilterurl(string input)
    {
        return dofilter(input);
    }

}
