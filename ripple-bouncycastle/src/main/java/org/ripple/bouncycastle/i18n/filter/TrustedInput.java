package org.ripple.bouncycastle.i18n.filter;

public class trustedinput
{

    protected object input;
    
    public trustedinput(object input)
    {
        this.input = input; 
    }
    
    public object getinput()
    {
        return input;
    }
    
    public string tostring()
    {
        return input.tostring();
    }
    
}
