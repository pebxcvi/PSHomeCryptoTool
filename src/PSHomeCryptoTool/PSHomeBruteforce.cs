using System;

public class PSHomeBruteforce
{
    private byte[] DecryptedFileBytes = null;
    private byte[] EncryptedFileBytes = null;

    public static string CurrentPrefix { get; set; } = string.Empty;
    public static bool StatusDebugEnabled { get; set; } = false;
    
    public static void PrintStatus(string message)
    {
        if (string.IsNullOrWhiteSpace(CurrentPrefix))
            Console.WriteLine(message);
        else
            Console.WriteLine($"{CurrentPrefix} ~ {message}");
    }

    public static void PrintErrorStatus(string message)
    {
        if (string.IsNullOrWhiteSpace(CurrentPrefix))
            Console.Error.WriteLine(message);
        else
            Console.Error.WriteLine($"{CurrentPrefix} ~ {message}");
    }

    public static void DebugStatus(string message)
    {
        if (!StatusDebugEnabled)
            return;

        if (string.IsNullOrWhiteSpace(CurrentPrefix))
            Console.WriteLine("[DEBUG] " + message);
        else
            Console.WriteLine($"{CurrentPrefix} [DEBUG] {message}");
    }

    public PSHomeBruteforce(byte[] EncryptedFileBytes)
    {
        this.EncryptedFileBytes = EncryptedFileBytes;
    }

    public byte[] StartBruteForce(ushort cdnMode, int mode = 0, int bruteforceTimeoutSeconds = 0)
    {
        if (EncryptedFileBytes != null)
        {
            DateTime timeStarted = DateTime.Now;

            byte[] TempBuffer = new byte[8];
            Buffer.BlockCopy(EncryptedFileBytes, 0, TempBuffer, 0, TempBuffer.Length);

            DecryptedFileBytes = CTRExploitProcess.ProcessExploit(TempBuffer, EncryptedFileBytes, mode, cdnMode, bruteforceTimeoutSeconds);

            if (DecryptedFileBytes != null)
                PrintStatus($"Resolved SHA1: {DotNetHasher.ComputeSHA1String(DecryptedFileBytes)}");
            else if (CTRExploitProcess.LastBruteforceTimedOut)
                PrintErrorStatus($"Bruteforce timed out after {bruteforceTimeoutSeconds} second(s)!");
            else
                PrintErrorStatus($"Nothing matched!");

            PrintStatus($"Time passed: {DateTime.Now.Subtract(timeStarted).TotalSeconds}s");
        }

        return DecryptedFileBytes;
    }
}