using System;
using System.Diagnostics;

public static class ThreadLimiter
{
    /*
        ThreadLimitMode meanings:

        -2 = RPCS3-aware auto
             If rpcs3 is running, use a lighter automatic limit.
             Otherwise use normal auto.

        -1 = Full CPU
             Uses Environment.ProcessorCount exactly.

         0 = Auto balanced
             Uses half of logical processors, minimum 1.

         1 = Force 1 thread

         2+ = Force exact manual thread count

        Final result is always clamped:
        - minimum 1
        - maximum Environment.ProcessorCount
    */
    public static int ThreadLimitMode = 0;

    public static int NumOfThreadsAvailable
    {
        get
        {
            int logical = Environment.ProcessorCount;
            int result;

            switch (ThreadLimitMode)
            {
                case -2:
                    bool rpcs3Running = Process.GetProcessesByName("rpcs3").Length > 0;
                    result = rpcs3Running
                        ? Math.Max(1, logical / 3)
                        : Math.Max(1, logical / 2);
                    break;

                case -1:
                    result = logical;
                    break;

                case 0:
                    result = Math.Max(1, logical / 2);
                    break;

                default:
                    result = ThreadLimitMode;
                    break;
            }

            if (result < 1)
                result = 1;

            if (result > logical)
                result = logical;

            return result;
        }
    }
}