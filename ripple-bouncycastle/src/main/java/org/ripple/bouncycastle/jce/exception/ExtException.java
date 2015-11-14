package org.ripple.bouncycastle.jce.exception;

/**
 * 
 * this is an extended exception. java before version 1.4 did not offer the
 * possibility the attach a cause to an exception. the cause of an exception is
 * the <code>throwable</code> object which was thrown and caused the
 * exception. this interface must be implemented by all exceptions to accomplish
 * this additional functionality.
 * 
 */
public interface extexception
{

    /**
     * returns the cause of the exception.
     * 
     * @return the cause of the exception.
     */
    throwable getcause();
}
