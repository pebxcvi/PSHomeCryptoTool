using System;
using System.IO;
using System.Threading.Tasks;
using SevenZip;
using SevenZip.Compression.LZMA;

public class LZMASegsCompressor
{
    private const uint SegsMagic = 0x73656773; // "segs"
    private const byte EdgeLzmaType = 1;
    private const byte FileVersion = 5;

    private const bool _eos = false;
    private const string _matchFinder = "BT4";

    private static readonly CoderPropID[] _propIDs = new CoderPropID[]
    {
        CoderPropID.Algorithm,
        CoderPropID.DictionarySize,
        CoderPropID.NumFastBytes,
        CoderPropID.LitContextBits,
        CoderPropID.LitPosBits,
        CoderPropID.PosStateBits,
        CoderPropID.MatchFinder,
        CoderPropID.EndMarker
    };

    private int MaxSegmentSize { get; set; }

    public LZMASegsCompressor(int maxSegmentSize)
    {
        MaxSegmentSize = maxSegmentSize;
    }

    private sealed class SegmentResult
    {
        public int UncompressedSize;
        public byte[] StoredBytes = Array.Empty<byte>();
        public bool IsCompressed;
    }

    public byte[] CompressToSegs(byte[] input, int level = 9)
    {
        return CompressToSegs(input, level, ThreadLimiter.NumOfThreadsAvailable);
    }

    public byte[] CompressToSegs(byte[] input, int level, int maxDegreeOfParallelism)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));
        else if (level < 0 || level > 9)
            throw new ArgumentOutOfRangeException(nameof(level), "[LZMASegsCompressor] - Compression level must be 0 through 9.");
        else if (maxDegreeOfParallelism <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxDegreeOfParallelism), "[LZMASegsCompressor] - maxDegreeOfParallelism must be greater than 0.");

        const int headerSizeOf = 16;
        int numSegments = (input.Length + (MaxSegmentSize - 1)) / MaxSegmentSize;
        int headerAndTocSize = headerSizeOf + (numSegments * 8);

        SegmentResult[] results = new SegmentResult[numSegments];

        Parallel.For(
            0,
            numSegments,
            new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism },
            segNo =>
            {
                int srcOffset = segNo * MaxSegmentSize;
                int uncompSegSize = Math.Min(MaxSegmentSize, input.Length - srcOffset);

                using (var inputStream = new MemoryStream())
                using (var outputStream = new MemoryStream())
                {
                    inputStream.Write(input, srcOffset, uncompSegSize);
                    inputStream.Position = 0;

                    SegmentCompress(inputStream, outputStream, level);

                    byte[] compressed = outputStream.ToArray();
                    bool storeCompressed = compressed.Length < uncompSegSize;

                    if (storeCompressed)
                    {
                        results[segNo] = new SegmentResult
                        {
                            UncompressedSize = uncompSegSize,
                            StoredBytes = compressed,
                            IsCompressed = true
                        };
                    }
                    else
                    {
                        byte[] rawSegment = new byte[uncompSegSize];
                        Array.Copy(input, srcOffset, rawSegment, 0, uncompSegSize);

                        results[segNo] = new SegmentResult
                        {
                            UncompressedSize = uncompSegSize,
                            StoredBytes = rawSegment,
                            IsCompressed = false
                        };
                    }
                }
            });

        byte[] toc = new byte[numSegments * 8];
        using (MemoryStream payload = new MemoryStream())
        {
            int fileOffset = headerAndTocSize;

            for (int segNo = 0; segNo < numSegments; segNo++)
            {
                SegmentResult result = results[segNo];
                int storedSize = result.StoredBytes.Length;

                WriteBE16(toc, segNo * 8 + 0, storedSize);
                WriteBE16(toc, segNo * 8 + 2, result.UncompressedSize);
                EndianAwareConverter.WriteUInt32(
                    toc,
                    Endianness.BigEndian,
                    (uint)(segNo * 8 + 4),
                    (uint)fileOffset + ((storedSize != result.UncompressedSize && result.IsCompressed) ? 1u : 0u)
                ); // Simulate the -1 SDK bug (according to test data).

                payload.Write(result.StoredBytes, 0, storedSize);

                fileOffset += storedSize;

                int remainder = fileOffset % headerSizeOf;
                if (remainder != 0)
                {
                    remainder = headerSizeOf - remainder;
                    byte[] padding = new byte[remainder];
                    payload.Write(padding, 0, padding.Length);
                    fileOffset += remainder;
                }
            }

            using (MemoryStream output = new MemoryStream(fileOffset))
            {
                WriteBE32(output, SegsMagic);
                output.WriteByte(EdgeLzmaType);
                output.WriteByte(FileVersion);
                WriteBE16(output, numSegments);
                WriteBE32(output, (uint)input.Length);
                WriteBE32(output, (uint)fileOffset);

                output.Write(toc, 0, toc.Length);

                payload.Position = 0;
                payload.CopyTo(output);

                return output.ToArray();
            }
        }
    }

    public static void SegmentCompress(Stream inStream, Stream outStream, int level)
    {
        Encoder encoder = new Encoder();

        int algorithm, dictSize, fastBytes, lc, lp, pb;
        GetEncoderProps(level, out algorithm, out dictSize, out fastBytes, out lc, out lp, out pb);

        encoder.SetCoderProperties(
            _propIDs,
            new object[]
            {
                algorithm,
                dictSize,
                fastBytes,
                lc,
                lp,
                pb,
                _matchFinder,
                _eos
            });

        encoder.WriteCoderProperties(outStream);

        long fileSize = inStream.Length;

        for (int i = 0; i < 8; i++)
            outStream.WriteByte((byte)(fileSize >> (8 * i)));

        encoder.Code(inStream, outStream, -1, -1, null);
    }

    private static void GetEncoderProps(int level, out int algorithm, out int dictSize, out int fastBytes, out int lc, out int lp, out int pb)
    {
        switch (level)
        {
            case 0:
                algorithm = 0; dictSize = 1024; fastBytes = 32; lc = 3; lp = 0; pb = 2;
                break;
            case 1:
                algorithm = 0; dictSize = 65536 / 16; fastBytes = 32; lc = 0; lp = 0; pb = 0;
                break;
            case 2:
                algorithm = 1; dictSize = 65536 / 16; fastBytes = 32; lc = 0; lp = 0; pb = 0;
                break;
            case 3:
                algorithm = 1; dictSize = 65536 / 8; fastBytes = 32; lc = 0; lp = 0; pb = 1;
                break;
            case 4:
                algorithm = 1; dictSize = 65536 / 8; fastBytes = 64; lc = 1; lp = 0; pb = 1;
                break;
            case 5:
                algorithm = 1; dictSize = 65536 / 4; fastBytes = 64; lc = 1; lp = 0; pb = 1;
                break;
            case 6:
                algorithm = 1; dictSize = 65536 / 4; fastBytes = 64; lc = 1; lp = 0; pb = 2;
                break;
            case 7:
                algorithm = 1; dictSize = 65536 / 2; fastBytes = 64; lc = 1; lp = 0; pb = 2;
                break;
            case 8:
                algorithm = 1; dictSize = 65536; fastBytes = 64; lc = 3; lp = 0; pb = 1;
                break;
            default:
                algorithm = 1; dictSize = 65536; fastBytes = 64; lc = 3; lp = 0; pb = 2;
                break;
        }
    }

    private static void WriteBE16(byte[] buffer, int offset, int value)
    {
        EndianAwareConverter.WriteUInt16(buffer, Endianness.BigEndian, (uint)offset, (ushort)(value == 65536 ? 0 : value));
    }

    private static void WriteBE16(Stream stream, int value)
    {
        ushort v = (ushort)(value == 65536 ? 0 : value);
        stream.WriteByte((byte)(v >> 8));
        stream.WriteByte((byte)v);
    }

    private static void WriteBE32(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }
}