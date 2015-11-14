package org.ripple.bouncycastle.i18n;

import java.io.unsupportedencodingexception;
import java.util.locale;
import java.util.timezone;

public class textbundle extends localizedmessage 
{

    /**
     * text entry key
     */
    public static final string text_entry = "text";
    
    /**
     * constructs a new textbundle using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     */
    public textbundle(string resource, string id) throws nullpointerexception 
    {
        super(resource, id);
    }
    
    /**
     * constructs a new textbundle using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param encoding the encoding of the resource file
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     * @throws unsupportedencodingexception if the encoding is not supported
     */
    public textbundle(string resource, string id, string encoding) throws nullpointerexception, unsupportedencodingexception 
    {
        super(resource, id, encoding);
    }

    /**
     * constructs a new textbundle using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param arguments an array containing the arguments for the message
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     */
    public textbundle(string resource, string id, object[] arguments) throws nullpointerexception 
    {
        super(resource, id, arguments);
    }
    
    /**
     * constructs a new textbundle using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param encoding the encoding of the resource file
     * @param arguments an array containing the arguments for the message
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     * @throws unsupportedencodingexception if the encoding is not supported
     */
    public textbundle(string resource, string id, string encoding, object[] arguments) throws nullpointerexception, unsupportedencodingexception 
    {
        super(resource, id, encoding, arguments);
    }
    
    /**
     * returns the text message in the given locale and timezone.
     * @param loc the {@link locale}
     * @param timezone the {@link timezone}
     * @return the text message.
     * @throws missingentryexception if the message is not available
     */
    public string gettext(locale loc, timezone timezone) throws missingentryexception
    {
        return getentry(text_entry,loc,timezone);
    }
    
    /**
     * returns the text message in the given locale and the defaut timezone.
     * @param loc the {@link locale}
     * @return the text message.
     * @throws missingentryexception if the message is not available
     */
    public string gettext(locale loc) throws missingentryexception
    {
        return getentry(text_entry,loc,timezone.getdefault());
    }

}
