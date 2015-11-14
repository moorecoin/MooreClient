package org.ripple.bouncycastle.i18n;

import java.io.unsupportedencodingexception;
import java.util.locale;

public class localestring extends localizedmessage
{

    public localestring(string resource, string id)
    {
        super(resource, id);
    }
    
    public localestring(string resource, string id, string encoding) throws nullpointerexception, unsupportedencodingexception
    {
        super(resource, id, encoding);
    }
    
    public string getlocalestring(locale locale)
    {
        return this.getentry(null, locale, null);
    }
    
}
