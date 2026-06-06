using System;
using System.IO;
// -- DEFINF2.0 --
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
// -- END --

public static class ToolsImplementation
{

    // -- DEFINF2.0 --
    public static readonly byte[] MetaDataV1Key = new byte[32]
    {
        0x8B, 0x41, 0xA7, 0xDE, 0x47, 0xA0, 0xD4, 0x45,
        0xE2, 0xA5, 0x90, 0x34, 0x3C, 0xD9, 0xA8, 0xB5,
        0x69, 0x5E, 0xFA, 0xD9, 0x97, 0x32, 0xEC, 0x56,
        0x0B, 0x31, 0xE8, 0x5A, 0xD1, 0x85, 0x7C, 0x89
    };

    public static readonly byte[] MetaDataV1IV = new byte[8] { 0x2a, 0xa7, 0xcb, 0x49, 0x9f, 0xa1, 0xbd, 0x81 };

    private static byte[] InitiateMetaDataV1IVA()
    {
        const ushort metaSize = 528;
        byte[] nulledBytes = new byte[metaSize];

        IBufferedCipher cipher = CipherUtilities.GetCipher("Blowfish/CTR/NOPADDING");
        cipher.Init(false, new ParametersWithIV(new KeyParameter(MetaDataV1Key), MetaDataV1IV));
        byte[] ciphertextBytes = new byte[cipher.GetOutputSize(metaSize)];
        int ciphertextLength = cipher.ProcessBytes(nulledBytes, 0, metaSize, ciphertextBytes, 0);
        cipher.DoFinal(ciphertextBytes, ciphertextLength);
        cipher = null;

        return ciphertextBytes;
    }

    public static readonly byte[] MetaDataV1IVA = InitiateMetaDataV1IVA();

    public static byte[] ApplyLittleEndianPaddingPrefix(byte[] filebytes)
    {
        return ByteUtils.CombineByteArray(new byte[] { 0x00, 0x00, 0x00, 0x01 }, filebytes);
    }

    public static byte[] RemovePaddingPrefix(byte[] fileBytes)
    {
        if (fileBytes.Length > 4 && ((fileBytes[0] == 0x00 && fileBytes[1] == 0x00 && fileBytes[2] == 0x00 && fileBytes[3] == 0x01)
            || (fileBytes[0] == 0x01 && fileBytes[1] == 0x00 && fileBytes[2] == 0x00 && fileBytes[3] == 0x00)))
        {
            byte[] destinationArray = new byte[fileBytes.Length - 4];
            Array.Copy(fileBytes, 4, destinationArray, 0, destinationArray.Length);
            return destinationArray;
        }
        return fileBytes;
    }
    
    public static void DecryptOrCopy(string inFile, string output, bool outputIsFile)
    {
        try
        {
            byte[] inputBytes = File.ReadAllBytes(inFile);

            string outFile = outputIsFile ? output : Path.Combine(output, Path.GetFileName(inFile));

            if (inputBytes.Length >= 4 &&
                inputBytes[0] == 0x00 && inputBytes[1] == 0x00 &&
                inputBytes[2] == 0x00 && inputBytes[3] == 0x01)
            {
                inputBytes = RemovePaddingPrefix(inputBytes);
                byte[] decrypted = LIBSECURE.Crypt_Decrypt(inputBytes, MetaDataV1IVA, 8);
                File.WriteAllBytes(outFile, decrypted);
            }
            else if (inputBytes.Length >= 4 &&
                     inputBytes[0] == 0xBE && inputBytes[1] == 0xE5 &&
                     inputBytes[2] == 0xBE && inputBytes[3] == 0xE5)
            {
                byte[] decrypted = LIBSECURE.Crypt_Decrypt(inputBytes, MetaDataV1IVA, 8);
                File.WriteAllBytes(outFile, decrypted);
            }
            else
            {
                File.Copy(inFile, outFile, true);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"ERROR: {inFile} -- {ex.Message}");
        }
    }
    // -- END --

    public static readonly byte[] BlowfishKey = new byte[32]
    {
        0x80, 0x6d, 0x79, 0x16, 0x23, 0x42, 0xa1, 0x0e,
        0x8f, 0x78, 0x14, 0xd4, 0xf9, 0x94, 0xa2, 0xd1,
        0x74, 0x13, 0xfc, 0xa8, 0xf6, 0xe0, 0xb8, 0xa4,
        0xed, 0xb9, 0xdc, 0x32, 0x7f, 0x8b, 0xa7, 0x11
    };
    public static readonly byte[] BetaBlowfishKey = new byte[32]
    {
        0x81, 0x61, 0xCB, 0x66, 0xEE, 0x70, 0xCD, 0x5E,
        0x80, 0x8D, 0xA5, 0xB5, 0xBC, 0x34, 0x4D, 0x74,
        0x71, 0x04, 0x4E, 0xC3, 0x6A, 0xFC, 0x3B, 0x24,
        0x1A, 0x03, 0xCE, 0xFD, 0x9B, 0x63, 0x0E, 0xBD
    };
    public static readonly byte[] HDKBlowfishKey = new byte[32]
    {
        0xF1, 0xC5, 1, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xF1, 0xC5, 1, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xF1, 0xC5, 1, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xF1, 0xC5, 1, 0x23, 0x45, 0x67, 0x89, 0xAB
    };

    //PsHomeCryptoEncrypt
    public static ulong Sha1toNonce(byte[] digest)
    {
        if (digest == null || digest.Length < 8)
            return 0UL;

        return BitConverter.ToUInt64(!BitConverter.IsLittleEndian ? EndianUtils.ReverseArray(digest) : digest, 0);
    }

    //PsHomeCryptoEncrypt
    private static byte[] ConvertSha1StringToByteArray(string sha1String)
    {
        if (sha1String.Length % 2 != 0)
        {
            Console.Error.WriteLine("[ToolsImplementation] - ConvertSha1StringToByteArray: Input string length must be even.");
            return null;
        }

        byte[] byteArray = new byte[sha1String.Length / 2];

        for (int i = 0; i < sha1String.Length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(sha1String.Substring(i, 2), 16);
        }

        return byteArray;
    }

    //PsHomeCryptoEncrypt
    public static byte[] CDSEncrypt_Decrypt(byte[] buffer, string sha1, ushort cdnMode)
    {
        byte[] digest = ConvertSha1StringToByteArray(sha1.ToUpper());
        if (digest != null)
        {
            switch (cdnMode)
            {
                case 2:
                    return LIBSECURE.InitiateBlowfishBuffer(
                        buffer,
                        HDKBlowfishKey,
                        BitConverter.GetBytes(!BitConverter.IsLittleEndian
                            ? EndianUtils.ReverseUlong(Sha1toNonce(digest))
                            : Sha1toNonce(digest)),
                        "CTR");

                case 1:
                    return LIBSECURE.InitiateBlowfishBuffer(
                        buffer,
                        BetaBlowfishKey,
                        BitConverter.GetBytes(!BitConverter.IsLittleEndian
                            ? EndianUtils.ReverseUlong(Sha1toNonce(digest))
                            : Sha1toNonce(digest)),
                        "CTR");

                default:
                    return LIBSECURE.InitiateBlowfishBuffer(
                        buffer,
                        BlowfishKey,
                        BitConverter.GetBytes(!BitConverter.IsLittleEndian
                            ? EndianUtils.ReverseUlong(Sha1toNonce(digest))
                            : Sha1toNonce(digest)),
                        "CTR");
            }
        }

        return null;
    }

    //PsHomeCryptoBruteforce
    public static void IncrementIVBytes(byte[] byteArray, int increment)
    {
        for (int i = byteArray.Length - 1; i > -1; i--)
        {
            int newValue = byteArray[i] + (byte)increment;
            byteArray[i] = (byte)newValue;
            increment = newValue >> 8; // Carry over the overflow to the next byte
            if (increment == 0)
                break; // No more overflow, we're done
        }
    }

    //PsHomeCryptoBruteforce
    public static byte[] ProcessCrypt_Decrypt(byte[] inData, byte[] KeyBytes, byte[] IV, byte mode)
    {
        return Task.Run(async() => {
            byte BlockSize;
            int chunkIndex = 0;
            int inputLength = inData.Length;
            List<KeyValuePair<(int, int), Task<byte[]>>> libsecureResults = new List<KeyValuePair<(int, int), Task<byte[]>>>();

            switch (mode)
            {
                case 0: // Xtea
                case 1: // Blowfish
                    BlockSize = 8;
                    break;
                case 2: // AES
                    BlockSize = 16;
                    break;
                default:
                    Console.Error.WriteLine($"[ToolsImplementation] - ProcessCrypt_Decrypt: unknown crypto mode selected:{mode}.");
                    return null;
            }

            using (MemoryStream memoryStream = new MemoryStream(inData))
            {
                while (memoryStream.Position < memoryStream.Length)
                {
                    Task<byte[]> libsecureResult;
                    byte[] block = new byte[BlockSize];
                    byte[] blockIV = IV.ShadowCopy();
                    int currentBlockSize = Math.Min(BlockSize, inputLength - chunkIndex);
                    if (currentBlockSize < BlockSize)
                    {
                        int difference = BlockSize - currentBlockSize;
                        Buffer.BlockCopy(new byte[difference], 0, block, block.Length - difference, difference);
                    }
                    memoryStream.Read(block, 0, currentBlockSize);
                    switch (mode)
                    {
                        case 0: // Xtea
                            libsecureResult = LIBSECURE.InitiateXTEABuffer(block, KeyBytes, blockIV, "CTR");
                            break;
                        case 1: // Blowfish
                            libsecureResult = LIBSECURE.InitiateBlowfishBufferASync(block, KeyBytes, blockIV, "CTR");
                            break;
                        default: // AES
                            libsecureResult = LIBSECURE.InitiateAESBuffer(block, KeyBytes, blockIV, "CTR");
                            break;
                    }
                    libsecureResults.Add(new KeyValuePair<(int, int), Task<byte[]>>((chunkIndex, currentBlockSize), libsecureResult));
                    IncrementIVBytes(IV, 1);
                    chunkIndex += currentBlockSize;
                }
            }

            using (MemoryStream memoryStream = new MemoryStream(inData.Length))
            {
                foreach (var result in libsecureResults.OrderBy(kv => kv.Key.Item1))
                {
                    byte[] decryptedChunk = await result.Value.ConfigureAwait(false);
                    if (decryptedChunk == null) // We failed.
                        return null;
                    if (decryptedChunk.Length < result.Key.Item2)
                        memoryStream.Write(decryptedChunk, 0, decryptedChunk.Length);
                    else
                        memoryStream.Write(decryptedChunk, 0, result.Key.Item2);
                }

                return memoryStream.ToArray();
            }
        }).Result;
    }

}
