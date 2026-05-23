using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class DotNetHasher
{
    public const string Sha1Const = "SHA1";

    public static byte[] ComputeSHA1(object input, byte[] HMACKey = null)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        byte[] result = ComputeObject(input, Sha1Const, HMACKey);

        if (result.Length != 20)
            throw new InvalidOperationException("[DotNetHasher] - ComputeSHA1 - The computed SHA1 hash is not 20 bytes long.");

        return result;
    }

    public static string ComputeSHA1String(object input, byte[] HMACKey = null)
    {
        return BitConverter.ToString(ComputeSHA1(input, HMACKey)).Replace("-", string.Empty);
    }

    private static byte[] ComputeObject(object inData, string hashName, byte[] HMACKey = null)
    {
        if (inData is byte[] bytes)
            return ComputeHash(bytes, hashName, HMACKey);
        else if (inData is string str)
            return ComputeHash(Encoding.Unicode.GetBytes(str), hashName, HMACKey);
        else if (inData is Stream stream)
            return ComputeStreamHash(stream, hashName, HMACKey);

        throw new ArgumentException($"[DotNetHasher] - ComputeObject - Unsupported data type: {inData.GetType()}", nameof(inData));
    }

    private static byte[] ComputeHash(byte[] data, string hashName, byte[] HMACKey)
    {
        if (hashName != Sha1Const)
            throw new ArgumentException($"[DotNetHasher] - ComputeHash - Unknown hash algorithm: {hashName}");

        if (HMACKey != null && HMACKey.Length > 0)
        {
            using HMACSHA1 hmac = new HMACSHA1(HMACKey);
            return hmac.ComputeHash(data);
        }

//#if NET6_0_OR_GREATER
       //return SHA1.HashData(data);
//#else
        using SHA1 sha1 = SHA1.Create();
        return sha1.ComputeHash(data);
//#endif
    }

    private static byte[] ComputeStreamHash(Stream stream, string hashName, byte[] HMACKey)
    {
        if (hashName != Sha1Const)
            throw new ArgumentException($"[DotNetHasher] - ComputeStreamHash - Unknown hash algorithm: {hashName}");

        if (HMACKey != null && HMACKey.Length > 0)
        {
            using HMACSHA1 hmac = new HMACSHA1(HMACKey);
            return hmac.ComputeHash(stream);
        }

//#if NET6_0_OR_GREATER
        //return SHA1.HashData(data);
//#else
        using SHA1 sha1 = SHA1.Create();
        return sha1.ComputeHash(stream);
//#endif
    }
}