
package org.ripple.bouncycastle.i18n.filter;

/**
 * wrapper class to mark untrusted input.
 */
public class untrustedinput 
{

    protected object input;

    /**
     * construct a new untrustedinput instance.
     * @param input the untrusted input object
     */
    public untrustedinput(object input) 
    {
        this.input = input;
    }

    /**
     * returns the untrusted input as object.
     * @return the <code>input</code> as object
     */
    public object getinput() 
    {
        return input;
    }

    /**
     * returns the untrusted input convertet to a string.
     * @return the <code>input</code> as string
     */
    public string getstring() 
    {
        return input.tostring();
    }
    
    public string tostring()
    {
        return input.tostring();
    }

}
