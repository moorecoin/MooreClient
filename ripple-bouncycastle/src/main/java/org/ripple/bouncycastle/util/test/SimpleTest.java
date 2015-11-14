package org.ripple.bouncycastle.util.test;

import java.io.printstream;

import org.ripple.bouncycastle.util.arrays;

public abstract class simpletest
    implements test
{
    public abstract string getname();

    private testresult success()
    {
        return simpletestresult.successful(this, "okay");
    }
    
    protected void fail(
        string message)
    {
        throw new testfailedexception(simpletestresult.failed(this, message));
    }
    
    protected void fail(
        string    message,
        throwable throwable)
    {
        throw new testfailedexception(simpletestresult.failed(this, message, throwable));
    }
    
    protected void fail(
        string message,
        object expected,
        object found)
    {
        throw new testfailedexception(simpletestresult.failed(this, message, expected, found));
    }
        
    protected boolean areequal(
        byte[] a,
        byte[] b)
    {
        return arrays.areequal(a, b);
    }
    
    public testresult perform()
    {
        try
        {
            performtest();
            
            return success();
        }
        catch (testfailedexception e)
        {
            return e.getresult();
        }
        catch (exception e)
        {
            return simpletestresult.failed(this, "exception: " +  e, e);
        }
    }
    
    protected static void runtest(
        test        test)
    {
        runtest(test, system.out);
    }
    
    protected static void runtest(
        test        test,
        printstream out)
    {
        testresult      result = test.perform();

        out.println(result.tostring());
        if (result.getexception() != null)
        {
            result.getexception().printstacktrace(out);
        }
    }

    public abstract void performtest()
        throws exception;
}
