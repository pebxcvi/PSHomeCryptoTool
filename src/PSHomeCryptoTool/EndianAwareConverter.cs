using System;
using System.Buffers.Binary;

public enum Endianness
{
        Automatic,
        LittleEndian,
        BigEndian

}

public static class EndianAwareConverter
{
    public static readonly bool isLittleEndianSystem = BitConverter.IsLittleEndian;
    #if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public static byte ToUInt8(ReadOnlySpan<byte> buf, Endianness endianness, uint address)
    {
        if (endianness != Endianness.Automatic)
            throw new ArgumentException("[EndianAwareConverter] - UInt8 reads doesn't have an endianness to resolve to");

        return buf[(int)address];
    }
    #endif

    public static int ToInt32(byte[] buf, Endianness endianness, uint address)
    {
    #if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        ReadOnlySpan<byte> span = buf.AsSpan((int)address, 4);
        return endianness == Endianness.LittleEndian
            ? BinaryPrimitives.ReadInt32LittleEndian(span)
            : BinaryPrimitives.ReadInt32BigEndian(span);
    #else
        if (endianness == (isLittleEndianSystem ? Endianness.LittleEndian : Endianness.BigEndian))
            return BitConverter.ToInt32(buf, (int)address);
        return BitConverter.ToInt32(new byte[4]
        {
            buf[(int)address + 3],
            buf[(int)address + 2],
            buf[(int)address + 1],
            buf[(int)address]
        }, 0);
    #endif
    }

    public static ushort ToUInt16(byte[] buf, Endianness endianness, uint address)
    {
        ReadOnlySpan<byte> span = buf.AsSpan((int)address, 2);
        return endianness == Endianness.LittleEndian
            ? BinaryPrimitives.ReadUInt16LittleEndian(span)
            : BinaryPrimitives.ReadUInt16BigEndian(span);
    }

    private static void CopyToBuffer(byte[] buf, byte[] bytes, uint address, bool trimAtStart)
    {
        long copyLength = Math.Min(bytes.Length, buf.LongLength - address);
        Array.Copy(bytes, trimAtStart ? bytes.Length - copyLength : 0, buf, address, copyLength);
    }

    public static void WriteUInt16(byte[] buf, Endianness endianness, uint address, ushort value, bool trimAtStart = false)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        if (endianness != (isLittleEndianSystem ? Endianness.LittleEndian : Endianness.BigEndian))
            Array.Reverse(bytes);
        CopyToBuffer(buf, bytes, address, trimAtStart);
    }

    public static void WriteUInt32(byte[] buf, Endianness endianness, uint address, uint value, bool trimAtStart = false)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        if (endianness != (isLittleEndianSystem ? Endianness.LittleEndian : Endianness.BigEndian))
            Array.Reverse(bytes);
        CopyToBuffer(buf, bytes, address, trimAtStart);
    }

}
