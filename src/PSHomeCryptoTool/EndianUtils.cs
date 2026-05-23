using System.Buffers.Binary;

public static class EndianUtils
{

    public static ulong ReverseUlong(ulong dataIn)
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        return BinaryPrimitives.ReverseEndianness(dataIn);
#else   
        return (0x00000000000000FF) & (dataIn >> 56)
             | (0x000000000000FF00) & (dataIn >> 40)
             | (0x0000000000FF0000) & (dataIn >> 24)
             | (0x00000000FF000000) & (dataIn >> 8)
             | (0x000000FF00000000) & (dataIn << 8)
             | (0x0000FF0000000000) & (dataIn << 24)
             | (0x00FF000000000000) & (dataIn << 40)
             | (0xFF00000000000000) & (dataIn << 56);
#endif
    }
        
    public static byte[] ReverseArray(byte[] dataIn)
    {
        if (dataIn == null)
            return null;
        // Clone the input array to avoid modifying the original array
        byte[] reversedArray = (byte[])dataIn.Clone();
        Array.Reverse(reversedArray);
        return reversedArray;
    }
    
    public static byte[] EndianSwap(byte[] dataIn)
    {
        if (dataIn == null)
            return null;

        const byte chunkSize = 4;

        int inputLength = dataIn.Length;

        if (inputLength <= chunkSize)
            return ReverseArray(dataIn);

        byte[] reversedArray = new byte[inputLength];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        ReadOnlySpan<byte> inputSpan = dataIn;
        Span<byte> outputSpan = reversedArray;

        int i = 0;

        while (i + chunkSize <= inputLength)
        {
            uint val = BitConverter.ToUInt32(inputSpan.Slice(i, chunkSize));
            val = BinaryPrimitives.ReverseEndianness(val);
            BitConverter.TryWriteBytes(outputSpan.Slice(i, chunkSize), val);
            i += chunkSize;
        }

        // Handle remaining bytes
        int remaining = inputLength - i;
        if (remaining > 0)
        {
            for (int j = 0; j < remaining; j++)
                reversedArray[i + j] = inputSpan[inputLength - j - 1];
        }
#else
        Array.Copy(dataIn, reversedArray, inputLength);

        int numofBytes;

        for (int i = 0; i < inputLength; i += numofBytes)
        {
            numofBytes = chunkSize;
            int remainingBytes = inputLength - i;
            if (remainingBytes < chunkSize)
                numofBytes = remainingBytes;
            Array.Reverse(reversedArray, i, numofBytes);
        }
#endif
        return reversedArray;
    }
}
