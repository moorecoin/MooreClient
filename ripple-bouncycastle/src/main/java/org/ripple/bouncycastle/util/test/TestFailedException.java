package org.ripple.bouncycastle.util.test;

public class testfailedexception 
    extends runtimeexception
{
    private testresult _result;
    
    public testfailedexception(
        testresult result)
    {
        _result = result;
    }
    
    public testresult getresult()
    {
        return _result;
    }
}
