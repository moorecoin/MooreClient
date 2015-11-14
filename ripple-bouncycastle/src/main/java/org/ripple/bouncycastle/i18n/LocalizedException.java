package org.ripple.bouncycastle.i18n;

import java.util.locale;

/**
 * base class for all exceptions with localized messages.
 */
public class localizedexception extends exception 
{

    protected errorbundle message;
    private throwable cause;
    
    /**
     * constructs a new localizedexception with the specified localized message.
     * @param message the {@link errorbundle} that contains the message for the exception
     */
    public localizedexception(errorbundle message) 
    {
        super(message.gettext(locale.getdefault()));
        this.message = message;
    }
    
    /**
     * constructs a new localizedexception with the specified localized message and cause.
     * @param message the {@link errorbundle} that contains the message for the exception
     * @param throwable the cause
     */
    public localizedexception(errorbundle message, throwable throwable) 
    {
        super(message.gettext(locale.getdefault()));
        this.message = message;
        this.cause = throwable;
    }
    
    /**
     * returns the localized error message of the exception.
     * @return the localized error message as {@link errorbundle}
     */
    public errorbundle geterrormessage() 
    {
        return message;
    }

    public throwable getcause()
    {
        return cause;
    }
}
