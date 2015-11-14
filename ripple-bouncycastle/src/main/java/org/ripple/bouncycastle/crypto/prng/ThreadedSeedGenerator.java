package org.ripple.bouncycastle.crypto.prng;

/**
 * a thread based seed generator - one source of randomness.
 * <p>
 * based on an idea from marcus lippert.
 * </p>
 */
public class threadedseedgenerator
{
    private class seedgenerator
        implements runnable
    {
        private volatile int counter = 0;
        private volatile boolean stop = false;

        public void run()
        {
            while (!this.stop)
            {
                this.counter++;
            }

        }

        public byte[] generateseed(
            int numbytes,
            boolean fast)
        {
            thread t = new thread(this);
            byte[] result = new byte[numbytes];
            this.counter = 0;
            this.stop = false;
            int last = 0;
            int end;

            t.start();
            if(fast)
            {
                end = numbytes;
            }
            else
            {
                end = numbytes * 8;
            }
            for (int i = 0; i < end; i++)
            {
                while (this.counter == last)
                {
                    try
                    {
                        thread.sleep(1);
                    }
                    catch (interruptedexception e)
                    {
                        // ignore
                    }
                }
                last = this.counter;
                if (fast)
                {
                    result[i] = (byte) (last & 0xff);
                }
                else
                {
                    int bytepos = i/8;
                    result[bytepos] = (byte) ((result[bytepos] << 1) | (last & 1));
                }

            }
            stop = true;
            return result;
        }
    }

    /**
     * generate seed bytes. set fast to false for best quality.
     * <p>
     * if fast is set to true, the code should be round about 8 times faster when
     * generating a long sequence of random bytes. 20 bytes of random values using
     * the fast mode take less than half a second on a nokia e70. if fast is set to false,
     * it takes round about 2500 ms.
     * </p>
     * @param numbytes the number of bytes to generate
     * @param fast true if fast mode should be used
     */
    public byte[] generateseed(
        int numbytes,
        boolean fast)
    {
        seedgenerator gen = new seedgenerator();

        return gen.generateseed(numbytes, fast);
    }
}
