package org.ripple.bouncycastle.i18n;

import org.ripple.bouncycastle.i18n.filter.filter;
import org.ripple.bouncycastle.i18n.filter.trustedinput;
import org.ripple.bouncycastle.i18n.filter.untrustedinput;
import org.ripple.bouncycastle.i18n.filter.untrustedurlinput;

import java.io.unsupportedencodingexception;
import java.nio.charset.charset;
import java.text.dateformat;
import java.text.format;
import java.text.messageformat;
import java.util.locale;
import java.util.missingresourceexception;
import java.util.resourcebundle;
import java.util.timezone;

public class localizedmessage 
{

    protected final string id;
    protected final string resource;
    
    // iso-8859-1 is the default encoding
    public static final string default_encoding = "iso-8859-1";
    protected string encoding = default_encoding;
    
    protected filteredarguments arguments;
    protected filteredarguments extraargs = null;
    
    protected filter filter = null;
    
    protected classloader loader = null;
    
    /**
     * constructs a new localizedmessage using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     */
    public localizedmessage(string resource,string id) throws nullpointerexception
    {
        if (resource == null || id == null)
        {
            throw new nullpointerexception();
        }
        this.id = id;
        this.resource = resource;
        arguments = new filteredarguments();
    }
    
    /**
     * constructs a new localizedmessage using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param encoding the encoding of the resource file
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     * @throws unsupportedencodingexception if the encoding is not supported
     */
    public localizedmessage(string resource,string id, string encoding) throws nullpointerexception, unsupportedencodingexception
    {
        if (resource == null || id == null)
        {
            throw new nullpointerexception();
        }
        this.id = id;
        this.resource = resource;
        arguments = new filteredarguments();
        if (!charset.issupported(encoding))
        {
            throw new unsupportedencodingexception("the encoding \"" + encoding + "\" is not supported.");
        }
        this.encoding = encoding;
    }
    
    /**
     * constructs a new localizedmessage using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param arguments an array containing the arguments for the message
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     */
    public localizedmessage(string resource, string id, object[] arguments) throws nullpointerexception
    {
        if (resource == null || id == null || arguments == null)
        {
            throw new nullpointerexception();
        }
        this.id = id;
        this.resource = resource;
        this.arguments = new filteredarguments(arguments);
    }
    
    /**
     * constructs a new localizedmessage using <code>resource</code> as the base name for the 
     * ressourcebundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param encoding the encoding of the resource file
     * @param arguments an array containing the arguments for the message
     * @throws nullpointerexception if <code>resource</code> or <code>id</code> is <code>null</code>
     * @throws unsupportedencodingexception if the encoding is not supported
     */
    public localizedmessage(string resource, string id, string encoding, object[] arguments) throws nullpointerexception, unsupportedencodingexception
    {
        if (resource == null || id == null || arguments == null)
        {
            throw new nullpointerexception();
        }
        this.id = id;
        this.resource = resource;
        this.arguments = new filteredarguments(arguments);
        if (!charset.issupported(encoding))
        {
            throw new unsupportedencodingexception("the encoding \"" + encoding + "\" is not supported.");
        }
        this.encoding = encoding;
    }
    
    /**
     * reads the entry <code>id + "." + key</code> from the resource file and returns a 
     * formated message for the given locale and timezone.
     * @param key second part of the entry id
     * @param loc the used {@link locale}
     * @param timezone the used {@link timezone}
     * @return a strng containing the localized message
     * @throws missingentryexception if the resource file is not available or the entry does not exist.
     */
    public string getentry(string key,locale loc, timezone timezone) throws missingentryexception
    {
        string entry = id;
        if (key != null)
        {
            entry += "." + key;
        }
        
        try
        {
            resourcebundle bundle;
            if (loader == null)
            {
                bundle = resourcebundle.getbundle(resource,loc);
            }
            else
            {
                bundle = resourcebundle.getbundle(resource, loc, loader);
            }
            string result = bundle.getstring(entry);
            if (!encoding.equals(default_encoding))
            {
                result = new string(result.getbytes(default_encoding), encoding);
            }
            if (!arguments.isempty())
            {
                result = formatwithtimezone(result,arguments.getfilteredargs(loc),loc,timezone);
            }
            result = addextraargs(result, loc);
            return result;
        }
        catch (missingresourceexception mre)
        {
            throw new missingentryexception("can't find entry " + entry + " in resource file " + resource + ".",
                    resource,
                    entry,
                    loc,
                    loader != null ? loader : this.getclassloader()); 
        }
        catch (unsupportedencodingexception use)
        {
            // should never occur - cause we already test this in the constructor
            throw new runtimeexception(use);
        }
    }
    
    protected string formatwithtimezone(
            string template,
            object[] arguments, 
            locale locale,
            timezone timezone) 
    {
        messageformat mf = new messageformat(" ");
        mf.setlocale(locale);
        mf.applypattern(template);
        if (!timezone.equals(timezone.getdefault())) 
        {
            format[] formats = mf.getformats();
            for (int i = 0; i < formats.length; i++) 
            {
                if (formats[i] instanceof dateformat) 
                {
                    dateformat temp = (dateformat) formats[i];
                    temp.settimezone(timezone);
                    mf.setformat(i,temp);
                }
            }
        }
        return mf.format(arguments);
    }
    
    protected string addextraargs(string msg, locale locale)
    {
        if (extraargs != null)
        {
            stringbuffer sb = new stringbuffer(msg);
            object[] filteredargs = extraargs.getfilteredargs(locale);
            for (int i = 0; i < filteredargs.length; i++)
            {
                sb.append(filteredargs[i]);
            }
            msg = sb.tostring();
        }
        return msg;
    }
    
    /**
     * sets the {@link filter} that is used to filter the arguments of this message
     * @param filter the {@link filter} to use. <code>null</code> to disable filtering.
     */
    public void setfilter(filter filter)
    {
        arguments.setfilter(filter);
        if (extraargs != null)
        {
            extraargs.setfilter(filter);
        }
        this.filter = filter;
    }
    
    /**
     * returns the current filter.
     * @return the current filter
     */
    public filter getfilter()
    {
        return filter;
    }
    
    /**
     * set the {@link classloader} which loads the resource files. if it is set to <code>null</code>
     * then the default {@link classloader} is used. 
     * @param loader the {@link classloader} which loads the resource files
     */
    public void setclassloader(classloader loader)
    {
        this.loader = loader;
    }
    
    /**
     * returns the {@link classloader} which loads the resource files or <code>null</code>
     * if the default classloader is used.
     * @return the {@link classloader} which loads the resource files
     */
    public classloader getclassloader()
    {
        return loader;
    }
    
    /**
     * returns the id of the message in the resource bundle.
     * @return the id of the message
     */
    public string getid()
    {
        return id;
    }
    
    /**
     * returns the name of the resource bundle for this message
     * @return name of the resource file
     */
    public string getresource()
    {
        return resource;
    }
    
    /**
     * returns an <code>object[]</code> containing the message arguments.
     * @return the message arguments
     */
    public object[] getarguments()
    {
        return arguments.getarguments();
    }
    
    /**
     * 
     * @param extraarg
     */
    public void setextraargument(object extraarg)
    {
        setextraarguments(new object[] {extraarg});
    }
    
    /**
     * 
     * @param extraargs
     */
    public void setextraarguments(object[] extraargs)
    {
        if (extraargs != null)
        {
            this.extraargs = new filteredarguments(extraargs);
            this.extraargs.setfilter(filter);
        }
        else
        {
            this.extraargs = null;
        }
    }
    
    /**
     * 
     * @return
     */
    public object[] getextraargs()
    {
        return (extraargs == null) ? null : extraargs.getarguments();
    }
    
    protected class filteredarguments
    {
        protected static final int no_filter = 0;
        protected static final int filter = 1;
        protected static final int filter_url = 2;
        
        protected filter filter = null;
        
        protected boolean[] islocalespecific;
        protected int[] argfiltertype;
        protected object[] arguments;
        protected object[] unpackedargs;
        protected object[] filteredargs;
        
        filteredarguments()
        {
            this(new object[0]);
        }
        
        filteredarguments(object[] args)
        {
            this.arguments = args;
            this.unpackedargs = new object[args.length];
            this.filteredargs = new object[args.length];
            this.islocalespecific = new boolean[args.length];
            this.argfiltertype = new int[args.length];
            for (int i = 0; i < args.length; i++)
            {
                if (args[i] instanceof trustedinput)
                {
                    this.unpackedargs[i] = ((trustedinput) args[i]).getinput();
                    argfiltertype[i] = no_filter;
                }
                else if (args[i] instanceof untrustedinput)
                {
                    this.unpackedargs[i] = ((untrustedinput) args[i]).getinput();
                    if (args[i] instanceof untrustedurlinput)
                    {
                        argfiltertype[i] = filter_url;
                    }
                    else
                    {
                        argfiltertype[i] = filter;
                    }
                }
                else
                {
                    this.unpackedargs[i] = args[i];
                    argfiltertype[i] = filter;
                }
                
                // locale specific
                this.islocalespecific[i] = (this.unpackedargs[i] instanceof localestring);
            }
        }
        
        public boolean isempty()
        {
            return unpackedargs.length == 0;
        }
        
        public object[] getarguments()
        {
            return arguments;
        }
        
        public object[] getfilteredargs(locale locale)
        {
            object[] result = new object[unpackedargs.length];
            for (int i = 0; i < unpackedargs.length; i++)
            {
                object arg;
                if (filteredargs[i] != null)
                {
                    arg = filteredargs[i];
                }
                else
                {
                    arg = unpackedargs[i];
                    if (islocalespecific[i])
                    {
                        // get locale
                        arg = ((localestring) arg).getlocalestring(locale);
                        arg = filter(argfiltertype[i], arg);
                    }
                    else
                    {
                        arg = filter(argfiltertype[i], arg);
                        filteredargs[i] = arg;
                    }
                }
                result[i] = arg;
            }
            return result;
        }
        
        private object filter(int type, object obj)
        {
            if (filter != null)
            {
                object o = (null == obj) ? "null" : obj;
                switch (type)
                {
                case no_filter:
                    return o;
                case filter:
                    return filter.dofilter(o.tostring());
                case filter_url:
                    return filter.dofilterurl(o.tostring());
                default:
                    return null;
                }
            }
            else
            {
                return obj;
            }
        }

        public filter getfilter()
        {
            return filter;
        }

        public void setfilter(filter filter)
        {
            if (filter != this.filter)
            {
                for (int i = 0; i < unpackedargs.length; i++)
                {
                    filteredargs[i] = null;
                }
            }
            this.filter = filter;
        }
        
    }
    
    public string tostring()
    {
        stringbuffer sb = new stringbuffer();
        sb.append("resource: \"").append(resource);
        sb.append("\" id: \"").append(id).append("\"");
        sb.append(" arguments: ").append(arguments.getarguments().length).append(" normal");
        if (extraargs != null && extraargs.getarguments().length > 0)
        {
            sb.append(", ").append(extraargs.getarguments().length).append(" extra");
        }
        sb.append(" encoding: ").append(encoding);
        sb.append(" classloader: ").append(loader);
        return sb.tostring();
    }

}
