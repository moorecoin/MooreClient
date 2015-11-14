package org.ripple.bouncycastle.util.test;

public class simpletestresult implements testresult
{
    private static final string separator = system.getproperty("line.separator");

    private boolean             success;
    private string              message;
    private throwable           exception;

    public simpletestresult(boolean success, string message)
    {
        this.success = success;
        this.message = message;
    }

    public simpletestresult(boolean success, string message, throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static testresult successful(
        test test, 
        string message)
    {
        return new simpletestresult(true, test.getname() + ": " + message);
    }

    public static testresult failed(
        test test, 
        string message)
    {
        return new simpletestresult(false, test.getname() + ": " + message);
    }
    
    public static testresult failed(
        test test, 
        string message, 
        throwable t)
    {
        return new simpletestresult(false, test.getname() + ": " + message, t);
    }
    
    public static testresult failed(
        test test, 
        string message, 
        object expected, 
        object found)
    {
        return failed(test, message + separator + "expected: " + expected + separator + "found   : " + found);
    }
    
    public static string failedmessage(string algorithm, string testname, string expected,
            string actual)
    {
        stringbuffer sb = new stringbuffer(algorithm);
        sb.append(" failing ").append(testname);
        sb.append(separator).append("    expected: ").append(expected);
        sb.append(separator).append("    got     : ").append(actual);

        return sb.tostring();
    }

    public boolean issuccessful()
    {
        return success;
    }

    public string tostring()
    {
        return message;
    }

    public throwable getexception()
    {
        return exception;
    }
}
