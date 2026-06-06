using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class PSHomeCryptoEncrypt
{
    private static bool DebugEnabled = false;

    private static readonly HashSet<string> SupportedExtensions =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".sdc",
            ".odc",
            ".sql",
            ".hcdb",
            ".xml",
            ".bar"
        };

    private static readonly Regex OdcRenameRegex = new Regex(
        @"^(?:(beta)\$)?(live2|live)\$([0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8})_T([0-9]{3})\.odc$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant
    );

    private static readonly Regex SdcRenameRegex = new Regex(
        @"^(?:(beta)\$)?(live2|live)\$([^$]+)\$([^\\\/$]+\.sdc)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant
    );

    private sealed class ToolConfig
    {
        public string OutputPath { get; set; } = string.Empty;
        public bool Debug { get; set; } = false;
        public int Threads { get; set; } = 0;
        public string Sha1 { get; set; } = string.Empty;
        public bool HcdbDecompress { get; set; } = true;
        public int HcdbCompressLevel { get; set; } = 9;
        public int HcdbCompressMaxSize { get; set; } = 65536;
        public ushort CdnMode { get; set; } = 0;
        public bool PauseOnExit { get; set; } = true;
        public bool CleanFolders { get; set; } = true;
        public bool WriteSha1Log { get; set; } = false;
        public bool OdcRename { get; set; } = false;
        public bool SdcRename { get; set; } = false;
    }

    private sealed class InputFileItem
    {
        public string FullPath { get; set; } = string.Empty;
        public string RelativePathWithoutTopFolder { get; set; } = string.Empty;
        public string InputRootFolderName { get; set; } = string.Empty;
        public bool InputHadSubfolders { get; set; } = false;

        public string Extension { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string DisplayInputPath { get; set; } = string.Empty;

        public bool IsSqlOrHcdb { get; set; } = false;
        public bool HasKnownSqlOrHcdbHeader { get; set; } = false;
        public bool UseDecryptOutputMode { get; set; } = false;
    }

    private sealed class OutputInfo
    {
        public string OutputFilePath { get; set; } = string.Empty;
        public string BucketRootPath { get; set; } = string.Empty;
        public string RelativePathInsideBucket { get; set; } = string.Empty;
        public string RelativeInputPath { get; set; } = string.Empty;
        public string Sha1ForLog { get; set; } = string.Empty;
        public string OutputExtension { get; set; } = string.Empty;
    }

    static int Main(string[] args)
    {
        int exitCode = 0;
        bool pauseOnExit = true;
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            string exeDir = AppContext.BaseDirectory;
            string configPath = Path.Combine(exeDir, "config-encrypt.ini");
            
            bool useConfigFile = !HasAnyOptionArgs(args);
            
            ToolConfig config;
            
            if (useConfigFile)
            {
                EnsureConfigExists(configPath);
                config = LoadConfig(configPath);
            }
            else
            {
                config = new ToolConfig();
            }

            List<string> inputPaths = new List<string>();
            string? cliOutputPath = null;
            bool? cliDebug = null;
            int? cliThreads = null;
            string? cliSha1 = null;
            bool? cliHcdbDecompress = null;
            int? cliHcdbCompressLevel = null;
            int? cliHcdbCompressMaxSize = null;
            ushort? cliCdnMode = null;
            bool? cliPauseOnExit = null;
            bool? cliCleanFolders = null;
            bool? cliWriteSha1Log = null;
            bool? cliOdcRename = null;
            bool? cliSdcRename = null;

            ParseArgs(
                args,
                inputPaths,
                ref cliOutputPath,
                ref cliDebug,
                ref cliThreads,
                ref cliSha1,
                ref cliHcdbDecompress,
                ref cliHcdbCompressLevel,
                ref cliHcdbCompressMaxSize,
                ref cliCdnMode,
                ref cliPauseOnExit,
                ref cliCleanFolders,
                ref cliWriteSha1Log,
                ref cliOdcRename,
                ref cliSdcRename
            );
            
            string effectiveOutputPath = !string.IsNullOrWhiteSpace(cliOutputPath)
                ? CleanOutputPath(cliOutputPath)
                : CleanOutputPath(config.OutputPath ?? string.Empty);
    
            DebugEnabled = cliDebug ?? config.Debug;
            int effectiveThreads = cliThreads ?? config.Threads;
            string effectiveSha1 = !string.IsNullOrWhiteSpace(cliSha1)
                ? cliSha1.Trim()
                : (config.Sha1?.Trim() ?? string.Empty);
            bool hcdbDecompress = cliHcdbDecompress ?? config.HcdbDecompress;
            int hcdbCompressLevel = cliHcdbCompressLevel ?? config.HcdbCompressLevel;
            int hcdbCompressMaxSize = cliHcdbCompressMaxSize ?? config.HcdbCompressMaxSize;
            ushort effectiveCdnMode = cliCdnMode ?? config.CdnMode;
            pauseOnExit = cliPauseOnExit ?? config.PauseOnExit;
            bool cleanFolders = cliCleanFolders ?? config.CleanFolders;
            bool writeSha1Log = cliWriteSha1Log ?? config.WriteSha1Log;
            bool odcRename = cliOdcRename ?? config.OdcRename;
            bool sdcRename = cliSdcRename ?? config.SdcRename;

            if (hcdbCompressLevel < 0 || hcdbCompressLevel > 9)
            {
                Console.WriteLine();
                Console.WriteLine("ERROR : ");
                Console.WriteLine();
                Console.WriteLine("    hcdbcompresslevel must be between 0 and 9.");
                exitCode = 1;
                return exitCode;
            }

            if (hcdbCompressMaxSize <= 0 || hcdbCompressMaxSize > 65536)
            {
                Console.WriteLine();
                Console.WriteLine("ERROR : ");
                Console.WriteLine();
                Console.WriteLine("    hcdbcompressmaxsize must be between 1 and 65536.");
                exitCode = 1;
                return exitCode;
            }

            ThreadLimiter.ThreadLimitMode = effectiveThreads;

            DebugLog($"Executable directory: {exeDir}");
            DebugLog($"Config path: {configPath}");
            DebugLog($"CLI args count: {args.Length}");
            DebugLog($"Effective outputpath: {effectiveOutputPath}");
            DebugLog($"Effective debug: {DebugEnabled}");
            DebugLog($"Effective threads mode: {effectiveThreads}");
            DebugLog($"Effective threads resolved: {ThreadLimiter.NumOfThreadsAvailable}");
            DebugLog($"Effective sha1: {(string.IsNullOrWhiteSpace(effectiveSha1) ? "<empty>" : effectiveSha1)}");
            DebugLog($"Effective hcdbDecompress: {hcdbDecompress}");
            DebugLog($"Effective hcdbcompresslevel: {hcdbCompressLevel}");
            DebugLog($"Effective hcdbcompressmaxsize: {hcdbCompressMaxSize}");
            DebugLog($"Effective cdnmode: {effectiveCdnMode}");
            DebugLog($"Effective pauseonexit: {pauseOnExit}");
            DebugLog($"Effective cleanfolders: {cleanFolders}");
            DebugLog($"Effective sha1log: {writeSha1Log}");
            DebugLog($"Effective odcrename: {odcRename}");
            DebugLog($"Effective sdcrename: {sdcRename}");

            if (inputPaths.Count == 0)
            {
                PrintUsage();
                exitCode = 1;
                return exitCode;
            }

            bool hasSuppliedSha1 = !string.IsNullOrWhiteSpace(effectiveSha1);

            List<InputFileItem> filesToProcess = ExpandInputPaths(inputPaths, hasSuppliedSha1);

            if (filesToProcess.Count == 0)
            {
                Console.WriteLine();
                Console.WriteLine("ERROR : ");
                Console.WriteLine();
                Console.WriteLine("    No supported files found to process.");
                exitCode = 1;
                return exitCode;
            }

            if (hasSuppliedSha1 && effectiveSha1.Length < 16)
            {
                Console.WriteLine();
                Console.WriteLine("ERROR : ");
                Console.WriteLine();
                Console.WriteLine("    Provided sha1 must be at least 16 hex characters.");
                exitCode = 1;
                return exitCode;
            }

            if (hasSuppliedSha1 && filesToProcess.Count != 1)
            {
                Console.WriteLine();
                Console.WriteLine("WARNING : ");
                Console.WriteLine();
                Console.WriteLine("    A supplied sha1 may only be used when exactly one supported file is being processed.");
                Console.WriteLine();
                Console.WriteLine("    Clear sha1 in config.ini or do not pass -sha1 when using a folder or multiple files.");
                exitCode = 1;
                return exitCode;
            }

            bool useDecryptOutputMode = hasSuppliedSha1 &&
                                        filesToProcess.Count == 1 &&
                                        filesToProcess[0].UseDecryptOutputMode;

            string outputRoot;
            if (!string.IsNullOrWhiteSpace(effectiveOutputPath))
            {
                outputRoot = Path.GetFullPath(effectiveOutputPath);
            }
            else
            {
                outputRoot = Path.Combine(
                    exeDir,
                    useDecryptOutputMode ? "Decrypted" : "Encrypted"
                );
            }

            if (cleanFolders)
            {
                CleanBucketFolders(outputRoot, filesToProcess, odcRename, sdcRename);
            }

            DebugLog($"Supported files found: {filesToProcess.Count}");
            DebugLog($"SHA1 mode: {(hasSuppliedSha1 ? "provided" : "self")}");
            DebugLog($"Use decrypt output mode: {useDecryptOutputMode}");
            DebugLog($"Output root: {outputRoot}");

            int successCount = 0;
            int failCount = 0;
            int skipCount = 0;
            int processedCount = 0;

            foreach (InputFileItem inputItem in filesToProcess)
            {
                try
                {
                    if (!IsSupportedExtension(inputItem.Extension))
                    {
                        skipCount++;
                        DebugLog($"Skipping unsupported extension: {inputItem.FullPath}");
                        continue;
                    }

                    if (!hasSuppliedSha1 && inputItem.IsSqlOrHcdb && !inputItem.HasKnownSqlOrHcdbHeader)
                    {
                        skipCount++;
                        string skipLabel = $"[{processedCount + 1}/{filesToProcess.Count}]";
                        Console.WriteLine($"{skipLabel} {inputItem.DisplayInputPath}");
                        Console.WriteLine($"{skipLabel} Already encrypted ... Skipping ...");
                        DebugLog($"Skipped due to unknown SQL/HCDB header: {inputItem.FullPath}");
                        continue;
                    }

                    processedCount++;
                    string progressLabel = $"[{processedCount}/{filesToProcess.Count}]";

                    Console.WriteLine($"{progressLabel} {inputItem.DisplayInputPath}");
                    DebugLog($"{progressLabel} Starting file: {inputItem.FullPath}");

                    OutputInfo outputInfo = ProcessSingleFile(
                        inputItem,
                        outputRoot,
                        effectiveSha1,
                        hcdbDecompress,
                        hcdbCompressLevel,
                        hcdbCompressMaxSize,
                        effectiveCdnMode,
                        hasSuppliedSha1,
                        odcRename,
                        sdcRename,
                        progressLabel
                    );

                    successCount++;

                    if (writeSha1Log)
                    {
                        AppendSha1Log(
                            outputInfo.BucketRootPath,
                            outputInfo.RelativePathInsideBucket,
                            outputInfo.Sha1ForLog,
                            outputInfo.OutputExtension
                        );
                        DebugLog($"{progressLabel} SHA1 log updated.");
                    }

                    DebugLog($"{progressLabel} Completed successfully.");
                }
                catch (Exception ex)
                {
                    failCount++;
                
                    Console.WriteLine($"[{processedCount}/{filesToProcess.Count}] ~ Failed!");
                    Console.WriteLine($"[{processedCount}/{filesToProcess.Count}] ~ ERROR : {ex.Message}");
                
                    if (DebugEnabled)
                        Console.WriteLine(ex.ToString());
                
                    DebugLog($"[{processedCount}/{filesToProcess.Count}] Failure processing file: {inputItem.FullPath}");
                    DebugLog(ex.ToString());
                }
            }

            stopwatch.Stop();

            Console.WriteLine();
            Console.WriteLine("Done.");
            Console.WriteLine($"Success: {successCount}");
            Console.WriteLine($"Failed: {failCount}");
            Console.WriteLine($"Skipped: {skipCount}");
            Console.WriteLine($"Elapsed: {FormatElapsed(stopwatch.Elapsed)}");

            exitCode = failCount == 0 ? 0 : 2;
            return exitCode;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            Console.WriteLine("Fatal error.");
            Console.WriteLine(DebugEnabled ? ex.ToString() : ex.Message);
            Console.WriteLine($"Elapsed: {FormatElapsed(stopwatch.Elapsed)}");
            exitCode = 99;
            return exitCode;
        }
        finally
        {
            PauseIfNeeded(pauseOnExit);
        }
    }

    private static void CleanBucketFolders(string outputRoot, List<InputFileItem> filesToProcess, bool odcRename, bool sdcRename)
    {
        HashSet<string> bucketNamesToClean = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (InputFileItem item in filesToProcess)
        {
            if (!IsSupportedExtension(item.Extension))
                continue;
        
            if (item.IsSqlOrHcdb &&
                !item.HasKnownSqlOrHcdbHeader &&
                !item.UseDecryptOutputMode)
            {
                DebugLog($"Clean skipped for unprocessable SQL/HCDB item: {item.FullPath}");
                continue;
            }
        
            string relativeOutputPath = GetOutputRelativePath(item, odcRename, sdcRename, item.UseDecryptOutputMode);
            string bucketName = GetBucketNameFromOutputRelativePath(relativeOutputPath);
        
            if (!string.IsNullOrWhiteSpace(bucketName))
                bucketNamesToClean.Add(bucketName);
        }

        foreach (string bucketName in bucketNamesToClean)
        {
            string bucketPath = Path.Combine(outputRoot, bucketName);
            if (Directory.Exists(bucketPath))
            {
                DebugLog($"Cleaning bucket folder: {bucketPath}");
                Directory.Delete(bucketPath, true);
            }
        }
    }

    private static OutputInfo ProcessSingleFile(
        InputFileItem inputItem,
        string outputRoot,
        string suppliedSha1,
        bool hcdbDecompress,
        int hcdbCompressLevel,
        int hcdbCompressMaxSize,
        ushort cdnMode,
        bool hasSuppliedSha1,
        bool odcRename,
        bool sdcRename,
        string progressLabel)
    {
        DebugLog($"{progressLabel} Reading: {inputItem.FullPath}");

        byte[] buffer = File.ReadAllBytes(inputItem.FullPath);
        DebugLog($"{progressLabel} Input length: {buffer.Length}");

        bool decryptMode = hasSuppliedSha1 && inputItem.UseDecryptOutputMode;
        byte[] workingBytes = buffer;
        byte[] bytesForWrite;
        byte[] bytesForSha1Log;
        string workingSha1;

        if (decryptMode)
        {
            PrintStep(progressLabel, "Decrypting ...");
            DebugLog($"{progressLabel} Entering decrypt mode.");

            byte[]? decrypted = null;
            try
            {
                workingSha1 = suppliedSha1.Substring(0, 16);
                DebugLog($"{progressLabel} Using supplied SHA1 prefix: {workingSha1}");
                DebugLog($"{progressLabel} Decrypting with cdnMode={cdnMode}");

                decrypted = ToolsImplementation.CDSEncrypt_Decrypt(workingBytes, workingSha1, cdnMode);

                if (decrypted == null)
                    throw new Exception("CDSEncrypt_Decrypt returned null.");

                PrintStep(progressLabel, "Decryption Successful!");
                DebugLog($"{progressLabel} Decryption output length: {decrypted.Length}");
            }
            catch (Exception ex)
            {
                PrintStep(progressLabel, "Decryption Failed!");
                DebugLog($"{progressLabel} Decryption exception: {ex}");
                throw;
            }

            bytesForWrite = decrypted;
            bytesForSha1Log = decrypted;

            if (inputItem.IsSqlOrHcdb)
            {
                if (hcdbDecompress)
                {
                    PrintStep(progressLabel, "Decompressing ...");
                    DebugLog($"{progressLabel} hcdbDecompress enabled.");

                    try
                    {
                        byte[]? decompressedData = LZMASegsDecompressor.SegmentsDecompress(decrypted, false);

                        if (decompressedData != null)
                        {
                            bytesForWrite = decompressedData;
                            PrintStep(progressLabel, "Decompression Successful!");
                            DebugLog($"{progressLabel} Decompression output length: {decompressedData.Length}");
                        }
                        else
                        {
                            PrintStep(progressLabel, "Decompression Failed!");
                            DebugLog($"{progressLabel} LZMASegsDecompressor.SegmentsDecompress returned null. Writing decrypted bytes as-is.");
                        }
                    }
                    catch (Exception ex)
                    {
                        PrintStep(progressLabel, "Decompression Failed!");
                        DebugLog($"{progressLabel} Decompression exception: {ex}");
                    }
                }
                else
                {
                    PrintStep(progressLabel, "Skipping Decompression ...");
                    DebugLog($"{progressLabel} hcdbDecompress disabled.");
                }
            }
        }
        else
        {
            DebugLog($"{progressLabel} Entering encrypt mode.");

            if (inputItem.IsSqlOrHcdb)
            {
                if (HasSqliteHeader(buffer))
                {
                    PrintStep(progressLabel, "Compressing ...");
                    DebugLog($"{progressLabel} SQLite header detected. Compressing to segs.");

                    try
                    {
                        workingBytes = new LZMASegsCompressor(hcdbCompressMaxSize).CompressToSegs(buffer, hcdbCompressLevel);
                        PrintStep(progressLabel, "Compression Successful!");
                        DebugLog($"{progressLabel} Compression output length: {workingBytes.Length}");
                    }
                    catch (Exception ex)
                    {
                        PrintStep(progressLabel, "Compression Failed!");
                        DebugLog($"{progressLabel} Compression exception: {ex}");
                        throw;
                    }
                }
                else
                {
                    PrintStep(progressLabel, "Skipping Compression ...");
                    DebugLog($"{progressLabel} Compression skipped because input already appears compressed or is not SQLite.");
                    workingBytes = buffer;
                }
            }
            else
            {
                DebugLog($"{progressLabel} Compression skipped because extension is not SQL/HCDB.");
                workingBytes = buffer;
            }

            PrintStep(progressLabel, "Encrypting ...");
            DebugLog($"{progressLabel} Preparing encryption.");

            try
            {
                if (hasSuppliedSha1 &&
                    inputItem.IsSqlOrHcdb &&
                    inputItem.HasKnownSqlOrHcdbHeader)
                {
                    workingSha1 = ComputeSHA1String(workingBytes).Substring(0, 16);
                    DebugLog($"{progressLabel} Supplied SHA1 ignored for SQL/HCDB with known header. Using file-derived SHA1 prefix: {workingSha1}");
                }
                else if (hasSuppliedSha1)
                {
                    workingSha1 = suppliedSha1.Substring(0, 16);
                    DebugLog($"{progressLabel} Using supplied SHA1 prefix: {workingSha1}");
                }
                else
                {
                    workingSha1 = ComputeSHA1String(workingBytes).Substring(0, 16);
                    DebugLog($"{progressLabel} Using file-derived SHA1 prefix: {workingSha1}");
                }

                DebugLog($"{progressLabel} Encrypting with cdnMode={cdnMode}");

                byte[]? encrypted = ToolsImplementation.CDSEncrypt_Decrypt(workingBytes, workingSha1, cdnMode);

                if (encrypted == null)
                    throw new Exception("CDSEncrypt_Decrypt returned null.");

                bytesForWrite = encrypted;
                bytesForSha1Log = workingBytes;

                PrintStep(progressLabel, "Encryption Successful!");
                DebugLog($"{progressLabel} Encryption output length: {encrypted.Length}");
            }
            catch (Exception ex)
            {
                PrintStep(progressLabel, "Encryption Failed!");
                DebugLog($"{progressLabel} Encryption exception: {ex}");
                throw;
            }
        }

        string relativeOutputPath = GetOutputRelativePath(inputItem, odcRename, sdcRename, inputItem.UseDecryptOutputMode);
        string bucketName = GetBucketNameFromOutputRelativePath(relativeOutputPath);
        string pathInsideBucket = RemoveLeadingBucketFolder(relativeOutputPath, bucketName);

        string bucketRootPath = Path.Combine(outputRoot, bucketName);
        string outputFilePath = Path.Combine(bucketRootPath, pathInsideBucket);
        string outputFolderPath = Path.GetDirectoryName(outputFilePath) ?? bucketRootPath;

        Directory.CreateDirectory(outputRoot);
        Directory.CreateDirectory(outputFolderPath);

        DebugLog($"{progressLabel} Writing: {outputFilePath}");
        DebugLog($"{progressLabel} Final output bytes length: {bytesForWrite.Length}");

        File.WriteAllBytes(outputFilePath, bytesForWrite);

        string sha1ForLog = ComputeSHA1String(bytesForSha1Log);

        return new OutputInfo
        {
            OutputFilePath = outputFilePath,
            BucketRootPath = bucketRootPath,
            RelativePathInsideBucket = NormalizePath(pathInsideBucket),
            RelativeInputPath = inputItem.DisplayInputPath,
            Sha1ForLog = sha1ForLog,
            OutputExtension = Path.GetExtension(outputFilePath)
        };
    }

    private static void AppendSha1Log(string bucketRootPath, string relativePathInsideBucket, string sha1, string outputExtension)
    {
        string logPath = Path.Combine(bucketRootPath, "sha1_hashes.txt");
        bool useXmlStyle = outputExtension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase);

        using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read))
        using (StreamWriter writer = new StreamWriter(fs, new UTF8Encoding(false)))
        {
            string normalizedPath = NormalizePath(relativePathInsideBucket);

            if (useXmlStyle)
            {
                string fileNameOnly = Path.GetFileName(normalizedPath);
                writer.WriteLine($"  <SHA1 digest=\"{sha1}\" file=\"Objects/{fileNameOnly}\"/>");
            }
            else
            {
                if (fs.Length == 0)
                    writer.WriteLine("File\tSHA1");

                writer.WriteLine($"{normalizedPath}\t{sha1}");
            }
        }
    }

    private static string GetOutputRelativePath(InputFileItem inputItem, bool odcRename, bool sdcRename, bool useDecryptOutputMode)
    {
        string ext = inputItem.Extension;
    
        string normalHostPrefix = string.Empty;
    
        if (inputItem.InputHadSubfolders &&
            !string.IsNullOrWhiteSpace(inputItem.InputRootFolderName))
        {
            normalHostPrefix = inputItem.InputRootFolderName;
        }
    
        if (ext.Equals(".odc", StringComparison.OrdinalIgnoreCase) && odcRename)
        {
            string? renamed = TryBuildRenamedOdcPath(inputItem.FileName, GetRenameHostPrefix(inputItem));
            if (!string.IsNullOrEmpty(renamed))
                return renamed;
        }
    
        if (ext.Equals(".sdc", StringComparison.OrdinalIgnoreCase) && sdcRename)
        {
            string? renamed = TryBuildRenamedSdcPath(inputItem.FileName, GetRenameHostPrefix(inputItem));
            if (!string.IsNullOrEmpty(renamed))
                return renamed;
        }
    
        string hostPrefix = normalHostPrefix;

        string bucketName;
        string dir = Path.GetDirectoryName(inputItem.RelativePathWithoutTopFolder) ?? string.Empty;
        string fileName;
        
        if (inputItem.IsSqlOrHcdb)
        {
            if (useDecryptOutputMode)
            {
                bucketName = "SQL";
                fileName = Path.GetFileNameWithoutExtension(inputItem.RelativePathWithoutTopFolder) + ".sql";
            }
            else if (inputItem.HasKnownSqlOrHcdbHeader)
            {
                bucketName = "HCDB";
                fileName = Path.GetFileNameWithoutExtension(inputItem.RelativePathWithoutTopFolder) + ".hcdb";
            }
            else
            {
                bucketName = ext.TrimStart('.').ToUpperInvariant();
                fileName = inputItem.FileName;
            }
        }
        else
        {
            bucketName = ext.TrimStart('.').ToUpperInvariant();
        
            if (!useDecryptOutputMode && inputItem.FileName.Equals("scenelist_dec.xml", StringComparison.OrdinalIgnoreCase))
                fileName = "Scenelist.xml";
            else
                fileName = inputItem.FileName;
        }

        if (string.IsNullOrEmpty(dir))
        {
            if (string.IsNullOrEmpty(hostPrefix))
                return Path.Combine(bucketName, fileName);

            return Path.Combine(bucketName, hostPrefix, fileName);
        }

        if (string.IsNullOrEmpty(hostPrefix))
            return Path.Combine(bucketName, dir, fileName);

        return Path.Combine(bucketName, hostPrefix, dir, fileName);
    }
    
    
    private static string GetRenameHostPrefix(InputFileItem inputItem)
    {
        if (string.IsNullOrWhiteSpace(inputItem.InputRootFolderName))
            return string.Empty;
    
        string rootName = inputItem.InputRootFolderName.Trim();
    
        if (rootName.EndsWith(".playstation.net", StringComparison.OrdinalIgnoreCase))
            return rootName;
    
        return string.Empty;
    }

    private static string? TryBuildRenamedOdcPath(string fileName, string hostPrefix)
    {
        Match match = OdcRenameRegex.Match(fileName);
        if (!match.Success)
            return null;

        string betaPrefix = match.Groups[1].Value;
        string liveToken = match.Groups[2].Value.ToLowerInvariant();
        string uuid = match.Groups[3].Value.ToUpperInvariant();
        string tValue = match.Groups[4].Value;

        string prodFolder = !string.IsNullOrEmpty(betaPrefix)
            ? "beta"
            : (liveToken == "live2" ? "prod2" : "prod");

        string liveFolder = liveToken == "live2" ? "live2" : "live";

        string objectFileName = tValue == "000"
            ? "object.odc"
            : $"object_T{tValue}.odc";

        if (string.IsNullOrEmpty(hostPrefix))
        {
            return Path.Combine(
                "ODC",
                "scee-home.playstation.net",
                "c.home",
                prodFolder,
                liveFolder,
                "Objects",
                uuid,
                objectFileName
            );
        }

        return Path.Combine(
            "ODC",
            hostPrefix,
            "c.home",
            prodFolder,
            liveFolder,
            "Objects",
            uuid,
            objectFileName
        );
    }

    private static string? TryBuildRenamedSdcPath(string fileName, string hostPrefix)
    {
        Match match = SdcRenameRegex.Match(fileName);
        if (!match.Success)
            return null;

        string betaPrefix = match.Groups[1].Value;
        string liveToken = match.Groups[2].Value.ToLowerInvariant();
        string sceneName = match.Groups[3].Value;
        string sceneFileName = match.Groups[4].Value;

        string prodFolder = !string.IsNullOrEmpty(betaPrefix)
            ? "beta"
            : (liveToken == "live2" ? "prod2" : "prod");

        string liveFolder = liveToken == "live2" ? "live2" : "live";

        if (string.IsNullOrEmpty(hostPrefix))
        {
            return Path.Combine(
                "SDC",
                "scee-home.playstation.net",
                "c.home",
                prodFolder,
                liveFolder,
                "Scenes",
                sceneName,
                sceneFileName
            );
        }

        return Path.Combine(
            "SDC",
            hostPrefix,
            "c.home",
            prodFolder,
            liveFolder,
            "Scenes",
            sceneName,
            sceneFileName
        );
    }

    private static string GetBucketNameFromOutputRelativePath(string relativeOutputPath)
    {
        string normalized = NormalizePath(relativeOutputPath);
        int slashIndex = normalized.IndexOf('\\');
        return slashIndex >= 0 ? normalized.Substring(0, slashIndex) : normalized;
    }

    private static string RemoveLeadingBucketFolder(string relativeOutputPath, string bucketName)
    {
        string normalized = NormalizePath(relativeOutputPath);

        if (normalized.Equals(bucketName, StringComparison.OrdinalIgnoreCase))
            return string.Empty;

        if (normalized.StartsWith(bucketName + "\\", StringComparison.OrdinalIgnoreCase))
            return normalized.Substring(bucketName.Length + 1);

        return normalized;
    }

    private static bool IsSupportedExtension(string ext)
    {
        return SupportedExtensions.Contains(ext);
    }

    private static bool ShouldUseDecryptOutputMode(string fullPath, string ext, bool hasSuppliedSha1, bool hasKnownSqlOrHcdbHeader)
    {
        if (!hasSuppliedSha1)
            return false;

        if (!ext.Equals(".sql", StringComparison.OrdinalIgnoreCase) &&
            !ext.Equals(".hcdb", StringComparison.OrdinalIgnoreCase))
            return true;

        if (hasKnownSqlOrHcdbHeader)
            return false;

        return true;
    }

    private static byte[] ReadHeaderBytes(string fullPath, int maxBytes)
    {
        byte[] buffer = new byte[maxBytes];

        using (FileStream fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            int bytesRead = fs.Read(buffer, 0, buffer.Length);

            if (bytesRead == buffer.Length)
                return buffer;

            byte[] trimmed = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, trimmed, 0, bytesRead);
            return trimmed;
        }
    }

   private static bool HasSqliteHeader(byte[] buffer)
   {
       if (buffer == null || buffer.Length < 6)
           return false;

       return buffer[0] == 0x53 &&
              buffer[1] == 0x51 &&
              buffer[2] == 0x4C &&
              buffer[3] == 0x69 &&
              buffer[4] == 0x74 &&
              buffer[5] == 0x65;
   }

    private static bool HasSegsHeader(byte[] buffer)
    {
        if (buffer == null || buffer.Length < 4)
            return false;

        return buffer[0] == 0x73 &&
               buffer[1] == 0x65 &&
               buffer[2] == 0x67 &&
               buffer[3] == 0x73;
    }

    private static List<InputFileItem> ExpandInputPaths(List<string> inputPaths, bool hasSuppliedSha1)
    {
        List<InputFileItem> results = new List<InputFileItem>(Math.Max(inputPaths.Count, 16));

        foreach (string path in inputPaths)
        {
            if (string.IsNullOrWhiteSpace(path))
                continue;

            DebugLog($"Expanding input path: {path}");

            if (File.Exists(path))
            {
                string fullPath = Path.GetFullPath(path);
                string ext = Path.GetExtension(fullPath);

                if (IsSupportedExtension(ext))
                {
                    string fileName = Path.GetFileName(fullPath);
                    string relativePath = fileName;

                    InputFileItem item = new InputFileItem
                    {
                        FullPath = fullPath,
                        RelativePathWithoutTopFolder = relativePath,
                        InputRootFolderName = string.Empty,
                        InputHadSubfolders = false,
                        Extension = ext,
                        FileName = fileName
                    };

                    PopulateCachedFields(item, hasSuppliedSha1);
                    results.Add(item);
                    DebugLog($"Added file input: {fullPath}");
                }
                else
                {
                    DebugLog($"Ignoring unsupported file: {path}");
                }
            }
            else if (Directory.Exists(path))
            {
                string rootPath = Path.GetFullPath(path);
                string rootFolderName = Path.GetFileName(rootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

                DebugLog($"Enumerating directory: {rootPath}");

                foreach (string file in Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories))
                {
                    string ext = Path.GetExtension(file);
                    if (!IsSupportedExtension(ext))
                        continue;

                    string relativeFromRoot = Path.GetRelativePath(rootPath, file);
                    bool hasSubfolders = NormalizePath(relativeFromRoot).Contains("\\");
                    string fileName = Path.GetFileName(file);

                    InputFileItem item = new InputFileItem
                    {
                        FullPath = file,
                        RelativePathWithoutTopFolder = relativeFromRoot,
                        InputRootFolderName = rootFolderName,
                        InputHadSubfolders = hasSubfolders,
                        Extension = ext,
                        FileName = fileName
                    };

                    PopulateCachedFields(item, hasSuppliedSha1);
                    results.Add(item);
                    DebugLog($"Added file from folder: {file}");
                }
            }
            else
            {
                DebugLog($"Input path does not exist: {path}");
            }
        }

        return results;
    }

    private static void PopulateCachedFields(InputFileItem item, bool hasSuppliedSha1)
    {
        item.IsSqlOrHcdb =
            item.Extension.Equals(".sql", StringComparison.OrdinalIgnoreCase) ||
            item.Extension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase);

        if (item.IsSqlOrHcdb)
        {
            byte[] headerBytes = ReadHeaderBytes(item.FullPath, 16);
            item.HasKnownSqlOrHcdbHeader = HasSqliteHeader(headerBytes) || HasSegsHeader(headerBytes);
            DebugLog($"Header probe for {item.FullPath}: HasKnownSqlOrHcdbHeader={item.HasKnownSqlOrHcdbHeader}");
        }
        else
        {
            item.HasKnownSqlOrHcdbHeader = false;
        }

        item.UseDecryptOutputMode = ShouldUseDecryptOutputMode(
            item.FullPath,
            item.Extension,
            hasSuppliedSha1,
            item.HasKnownSqlOrHcdbHeader
        );

        item.DisplayInputPath = BuildDisplayInputPath(item);

        DebugLog($"Cached fields for {item.FullPath}: IsSqlOrHcdb={item.IsSqlOrHcdb}, UseDecryptOutputMode={item.UseDecryptOutputMode}, DisplayInputPath={item.DisplayInputPath}");
    }

    private static string BuildDisplayInputPath(InputFileItem inputItem)
    {
        if (inputItem.InputHadSubfolders &&
            !string.IsNullOrWhiteSpace(inputItem.InputRootFolderName))
        {
            return NormalizePath(Path.Combine(inputItem.InputRootFolderName, inputItem.RelativePathWithoutTopFolder));
        }

        return NormalizePath(inputItem.RelativePathWithoutTopFolder);
    }
    
    
    private static bool HasAnyOptionArgs(string[] args)
    {
        if (args == null)
            return false;
    
        foreach (string arg in args)
        {
            if (string.IsNullOrWhiteSpace(arg))
                continue;
    
            if (arg.StartsWith("-", StringComparison.Ordinal) ||
                arg.StartsWith("/", StringComparison.Ordinal))
            {
                return true;
            }
        }
    
        return false;
    }

    private static void ParseArgs(
        string[] args,
        List<string> inputPaths,
        ref string? cliOutputPath,
        ref bool? cliDebug,
        ref int? cliThreads,
        ref string? cliSha1,
        ref bool? cliHcdbDecompress,
        ref int? cliHcdbCompressLevel,
        ref int? cliHcdbCompressMaxSize,
        ref ushort? cliCdnMode,
        ref bool? cliPauseOnExit,
        ref bool? cliCleanFolders,
        ref bool? cliWriteSha1Log,
        ref bool? cliOdcRename,
        ref bool? cliSdcRename)
    {
        if (args == null || args.Length == 0)
            return;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (string.IsNullOrWhiteSpace(arg))
                continue;

            if (arg.Equals("-outputpath", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/outputpath", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length)
                    cliOutputPath = args[++i].Trim();
                continue;
            }

            if (arg.Equals("-debug", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/debug", StringComparison.OrdinalIgnoreCase))
            {
                cliDebug = true;
                continue;
            }

            if (arg.Equals("-nodebug", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nodebug", StringComparison.OrdinalIgnoreCase))
            {
                cliDebug = false;
                continue;
            }

            if (arg.Equals("-threads", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/threads", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length && int.TryParse(args[++i], out int parsedThreads))
                    cliThreads = parsedThreads;
                continue;
            }

            if (arg.Equals("-sha1", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/sha1", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length)
                    cliSha1 = args[++i].Trim();
                continue;
            }

            if (arg.Equals("-hcdbdecompress", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbdecompress", StringComparison.OrdinalIgnoreCase))
            {
                cliHcdbDecompress = true;
                continue;
            }

            if (arg.Equals("-nohcdbdecompress", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nohcdbdecompress", StringComparison.OrdinalIgnoreCase))
            {
                cliHcdbDecompress = false;
                continue;
            }

            if (arg.Equals("-hcdbcompresslevel", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbcompresslevel", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length && int.TryParse(args[++i], out int parsedCompressLevel))
                    cliHcdbCompressLevel = parsedCompressLevel;
                continue;
            }

            if (arg.Equals("-hcdbcompressmaxsize", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbcompressmaxsize", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length && int.TryParse(args[++i], out int parsedCompressMaxSize))
                    cliHcdbCompressMaxSize = parsedCompressMaxSize;
                continue;
            }

            if (arg.Equals("-cdnmode", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/cdnmode", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length && ushort.TryParse(args[++i], out ushort parsedMode))
                    cliCdnMode = parsedMode;
                continue;
            }

            if (arg.Equals("-pause", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/pause", StringComparison.OrdinalIgnoreCase))
            {
                cliPauseOnExit = true;
                continue;
            }

            if (arg.Equals("-nopause", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nopause", StringComparison.OrdinalIgnoreCase))
            {
                cliPauseOnExit = false;
                continue;
            }

            if (arg.Equals("-cleanfolders", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/cleanfolders", StringComparison.OrdinalIgnoreCase))
            {
                cliCleanFolders = true;
                continue;
            }

            if (arg.Equals("-nocleanfolders", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nocleanfolders", StringComparison.OrdinalIgnoreCase))
            {
                cliCleanFolders = false;
                continue;
            }

            if (arg.Equals("-sha1log", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/sha1log", StringComparison.OrdinalIgnoreCase))
            {
                cliWriteSha1Log = true;
                continue;
            }

            if (arg.Equals("-nosha1log", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nosha1log", StringComparison.OrdinalIgnoreCase))
            {
                cliWriteSha1Log = false;
                continue;
            }

            if (arg.Equals("-odcrename", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/odcrename", StringComparison.OrdinalIgnoreCase))
            {
                cliOdcRename = true;
                continue;
            }

            if (arg.Equals("-noodcrename", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/noodcrename", StringComparison.OrdinalIgnoreCase))
            {
                cliOdcRename = false;
                continue;
            }

            if (arg.Equals("-sdcrename", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/sdcrename", StringComparison.OrdinalIgnoreCase))
            {
                cliSdcRename = true;
                continue;
            }

            if (arg.Equals("-nosdcrename", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nosdcrename", StringComparison.OrdinalIgnoreCase))
            {
                cliSdcRename = false;
                continue;
            }

            inputPaths.Add(arg);
        }
    }

    private static void EnsureConfigExists(string configPath)
    {
        if (File.Exists(configPath))
            return;

        StringBuilder sb = new StringBuilder();
        sb.AppendLine("outputpath=");
        sb.AppendLine("debug=false");
        sb.AppendLine("threads=0");
        sb.AppendLine("; ");
        sb.AppendLine("; Thread Limiter Definitions:");
        sb.AppendLine("; ");
        sb.AppendLine("; -2 = RPCS3-aware auto");
        sb.AppendLine(";     If rpcs3 is running, use a lighter automatic limit.");
        sb.AppendLine(";     Otherwise use normal auto.");
        sb.AppendLine("; ");
        sb.AppendLine("; -1 = Full CPU");
        sb.AppendLine(";     Uses Environment.ProcessorCount exactly.");
        sb.AppendLine(";     Example: if system reports 24 logical processors, use 24.");
        sb.AppendLine("; ");
        sb.AppendLine("; 0 = Auto balanced");
        sb.AppendLine(";     Uses a conservative automatic value so CPU is not overkilled.");
        sb.AppendLine(";     Current rule: half of logical processors, minimum 1.");
        sb.AppendLine(";     Example: 24 -> 12, 8 -> 4, 1 -> 1.");
        sb.AppendLine("; ");
        sb.AppendLine("; 1 = Force 1 thread");
        sb.AppendLine(";     Lowest manual setting.");
        sb.AppendLine("; ");
        sb.AppendLine("; 2+ = Force exact manual thread count");
        sb.AppendLine(";     Example: 4 = use 4 threads, 8 = use 8 threads.");
        sb.AppendLine("; ");
        sb.AppendLine("sha1=");
        sb.AppendLine("; ");
        sb.AppendLine("; - Manual SHA1 input : Only works when processing one file.");
        sb.AppendLine("; - Used for decrypting when the file's SHA1 is already known.");
        sb.AppendLine("; - For multiple files, PSHomeCryptoBruteforce is recommended.");
        sb.AppendLine("; ");
        sb.AppendLine("hcdbdecompress=true");
        sb.AppendLine("; ");
        sb.AppendLine("; - Used in conjunction with manual SHA1 input : If SQL/HCDB, decompresses from segs to SQLite.");
        sb.AppendLine("; ");
        sb.AppendLine("hcdbcompresslevel=9");
        sb.AppendLine("; ");
        sb.AppendLine("; - HCDB compression level used when compressing SQLite to segs.");
        sb.AppendLine("; ");
        sb.AppendLine("hcdbcompressmaxsize=65536");
        sb.AppendLine("; ");
        sb.AppendLine("; - HCDB segment size used when compressing SQLite to segs.");
        sb.AppendLine("; ");
        sb.AppendLine("cdnmode=0");
        sb.AppendLine("; ");
        sb.AppendLine("; cdnmode Definitions:");
        sb.AppendLine("; ");
        sb.AppendLine(";  0 = Default / Retail Blowfish key");
        sb.AppendLine(";  1 = Beta Blowfish key");
        sb.AppendLine(";  2 = HDK Blowfish key");
        sb.AppendLine("; ");
        sb.AppendLine("pauseonexit=true");
        sb.AppendLine("cleanfolders=true");
        sb.AppendLine("sha1log=true");
        sb.AppendLine("; ");
        sb.AppendLine("; - Writes sha1_hashes.txt in each output bucket.");
        sb.AppendLine("; ");
        sb.AppendLine("odcrename=false");
        sb.AppendLine("; - Restructures ODC files with the format (beta)$live(2)$UUID_TXXX.odc to CDN structure.");
        sb.AppendLine("; ");
        sb.AppendLine("sdcrename=false");
        sb.AppendLine("; - Restructures SDC files with the format (beta)$live(2)$SceneName$SceneFileName.sdc to CDN structure.");

        File.WriteAllText(configPath, sb.ToString(), new UTF8Encoding(false));
    }

    private static ToolConfig LoadConfig(string configPath)
    {
        ToolConfig config = new ToolConfig();

        if (!File.Exists(configPath))
            return config;

        foreach (string rawLine in File.ReadLines(configPath))
        {
            string line = rawLine.Trim();

            if (line.Length == 0)
                continue;
            if (line.StartsWith(";") || line.StartsWith("#"))
                continue;
            if (line.StartsWith("[") && line.EndsWith("]"))
                continue;

            int equalsIndex = line.IndexOf('=');
            if (equalsIndex <= 0)
                continue;

            string key = line.Substring(0, equalsIndex).Trim();
            string value = line.Substring(equalsIndex + 1).Trim();

            if (key.Equals("outputpath", StringComparison.OrdinalIgnoreCase))
            {
                config.OutputPath = value;
            }
            else if (key.Equals("debug", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedDebug))
                    config.Debug = parsedDebug;
            }
            else if (key.Equals("threads", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(value, out int parsedThreads))
                    config.Threads = parsedThreads;
            }
            else if (key.Equals("sha1", StringComparison.OrdinalIgnoreCase))
            {
                config.Sha1 = value;
            }
            else if (key.Equals("hcdbdecompress", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedHcdbDecompress))
                    config.HcdbDecompress = parsedHcdbDecompress;
            }
            else if (key.Equals("hcdbcompresslevel", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(value, out int parsedHcdbCompressLevel))
                    config.HcdbCompressLevel = parsedHcdbCompressLevel;
            }
            else if (key.Equals("hcdbcompressmaxsize", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(value, out int parsedHcdbCompressMaxSize))
                    config.HcdbCompressMaxSize = parsedHcdbCompressMaxSize;
            }
            else if (key.Equals("cdnmode", StringComparison.OrdinalIgnoreCase))
            {
                if (ushort.TryParse(value, out ushort parsedMode))
                    config.CdnMode = parsedMode;
            }
            else if (key.Equals("pauseonexit", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedPauseOnExit))
                    config.PauseOnExit = parsedPauseOnExit;
            }
            else if (key.Equals("cleanfolders", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedCleanFolders))
                    config.CleanFolders = parsedCleanFolders;
            }
            else if (key.Equals("sha1log", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedSha1Log))
                    config.WriteSha1Log = parsedSha1Log;
            }
            else if (key.Equals("odcrename", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedOdcRename))
                    config.OdcRename = parsedOdcRename;
            }
            else if (key.Equals("sdcrename", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedSdcRename))
                    config.SdcRename = parsedSdcRename;
            }
        }

        return config;
    }

    private static bool TryParseBool(string value, out bool result)
    {
        if (bool.TryParse(value, out result))
            return true;

        if (string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "y", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "on", StringComparison.OrdinalIgnoreCase))
        {
            result = true;
            return true;
        }

        if (string.Equals(value, "0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "no", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "n", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "off", StringComparison.OrdinalIgnoreCase))
        {
            result = false;
            return true;
        }

        result = false;
        return false;
    }

    private static string ComputeSHA1String(byte[] buffer)
    {
        using (SHA1 sha1 = SHA1.Create())
        {
            byte[] hash = sha1.ComputeHash(buffer);
            return BitConverter.ToString(hash).Replace("-", "");
        }
    }
    
    private static string CleanOutputPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;
    
        string cleaned = path.Trim();
    
        string root = Path.GetPathRoot(cleaned) ?? string.Empty;
    
        while (cleaned.Length > root.Length &&
               (cleaned.EndsWith("\\", StringComparison.Ordinal) ||
                cleaned.EndsWith("/", StringComparison.Ordinal)))
        {
            cleaned = cleaned.Substring(0, cleaned.Length - 1);
        }
    
        return cleaned;
    }

    private static string NormalizePath(string path)
    {
        return path.Replace(Path.DirectorySeparatorChar, '\\')
                   .Replace(Path.AltDirectorySeparatorChar, '\\');
    }

    private static string FormatElapsed(TimeSpan elapsed)
    {
        if (elapsed.TotalHours >= 1)
            return elapsed.ToString(@"hh\:mm\:ss\.fff");

        return elapsed.ToString(@"mm\:ss\.fff");
    }

    private static void DebugLog(string message)
    {
        if (!DebugEnabled)
            return;
    
        if (!string.IsNullOrEmpty(message) &&
            message.Length > 2 &&
            message[0] == '[')
        {
            int end = message.IndexOf(']');
            if (end > 0 && end + 1 < message.Length && message[end + 1] == ' ')
            {
                string prefix = message.Substring(0, end + 1);
                string rest = message.Substring(end + 2);
    
                Console.WriteLine($"[DEBUG] {prefix} {rest}");
                return;
            }
        }
    
        Console.WriteLine("[DEBUG] " + message);
    }

    private static void PrintStep(string progressLabel, string text)
    {
        Console.WriteLine($"{progressLabel} ~ {text}");
    }

    private static void PauseIfNeeded(bool pauseOnExit)
    {
        if (!pauseOnExit)
            return;

        Console.WriteLine();
        Console.WriteLine("Press any key to close ...");
        Console.ReadKey(true);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("PSHomeCryptoEncrypt");
        Console.WriteLine();
        Console.WriteLine("Supported extensions: .sdc .odc .sql .hcdb .xml .bar");
        Console.WriteLine("Drag and drop files and/or folders onto the EXE");
        Console.WriteLine("or use:");
        Console.WriteLine();
        Console.WriteLine("  PSHomeCryptoEncrypt.exe [files/folders...]");
        Console.WriteLine("   [-outputpath PATH]");
        Console.WriteLine("   [-debug]");
        Console.WriteLine("   [-threads -2|-1|0|1|2+]");
        Console.WriteLine("   [-sha1 HEX]");
        Console.WriteLine("   [-hcdbdecompress|-nohcdbdecompress]");
        Console.WriteLine("   [-hcdbcompresslevel N]");
        Console.WriteLine("   [-hcdbcompressmaxsize N]");
        Console.WriteLine("   [-cdnmode 0|1|2]");
        Console.WriteLine("   [-pause|-nopause]");
        Console.WriteLine("   [-cleanfolders|-nocleanfolders]");
        Console.WriteLine("   [-sha1log]");
        Console.WriteLine("   [-odcrename|-noodcrename]");
        Console.WriteLine("   [-sdcrename|-nosdcrename]");
        Console.WriteLine();
        Console.WriteLine("config-encrypt.ini:");
        Console.WriteLine();
        Console.WriteLine("  outputpath=");
        Console.WriteLine("  debug=false");
        Console.WriteLine("  threads=0");
        Console.WriteLine();
        Console.WriteLine("Thread Limiter Definitions:");
        Console.WriteLine();
        Console.WriteLine(" -2 = RPCS3-aware auto");
        Console.WriteLine("     If rpcs3 is running, use a lighter automatic limit.");
        Console.WriteLine("     Otherwise use normal auto.");
        Console.WriteLine();
        Console.WriteLine(" -1 = Full CPU");
        Console.WriteLine("     Uses Environment.ProcessorCount exactly.");
        Console.WriteLine("     Example: if system reports 24 logical processors, use 24.");
        Console.WriteLine();
        Console.WriteLine(" 0 = Auto balanced");
        Console.WriteLine("     Uses a conservative automatic value so CPU is not overkilled.");
        Console.WriteLine("     Current rule: half of logical processors, minimum 1.");
        Console.WriteLine("     Example: 24 -> 12, 8 -> 4, 1 -> 1.");
        Console.WriteLine();
        Console.WriteLine(" 1 = Force 1 thread");
        Console.WriteLine("     Lowest manual setting.");
        Console.WriteLine();
        Console.WriteLine(" 2+ = Force exact manual thread count");
        Console.WriteLine("     Example: 4 = use 4 threads, 8 = use 8 threads.");
        Console.WriteLine();
        Console.WriteLine("  sha1=");
        Console.WriteLine();
        Console.WriteLine("     - Manual SHA1 input : Only works when processing one file.");
        Console.WriteLine("     - Used for decrypting when the file's SHA1 is already known.");
        Console.WriteLine("     - For multiple files, PSHomeCryptoBruteforce is recommended.");
        Console.WriteLine();
        Console.WriteLine("  hcdbdecompress=true");
        Console.WriteLine();
        Console.WriteLine("     - Used in conjunction with manual SHA1 input : If SQL/HCDB, decompresses from segs to SQLite.");
        Console.WriteLine();
        Console.WriteLine("  hcdbcompresslevel=9");
        Console.WriteLine("     - HCDB compression level used when compressing SQLite to segs.");
        Console.WriteLine();
        Console.WriteLine("  hcdbcompressmaxsize=65536");
        Console.WriteLine("     - HCDB segment size used when compressing SQLite to segs.");
        Console.WriteLine();
        Console.WriteLine("  cdnmode=0");
        Console.WriteLine();
        Console.WriteLine("cdnmode Definitions:");
        Console.WriteLine();
        Console.WriteLine("  0 = Default / Retail Blowfish key");
        Console.WriteLine("  1 = Beta Blowfish key");
        Console.WriteLine("  2 = HDK Blowfish key");
        Console.WriteLine();
        Console.WriteLine("  pauseonexit=true");
        Console.WriteLine("  cleanfolders=true");
        Console.WriteLine("  sha1log=true");
        Console.WriteLine("     - Writes sha1_hashes.txt in each output bucket.");
        Console.WriteLine();
        Console.WriteLine("  odcrename=false");
        Console.WriteLine("     - Restructures ODC files with the format (beta)$live(2)$UUID_TXXX.odc to CDN structure.");
        Console.WriteLine();
        Console.WriteLine("  sdcrename=false");
        Console.WriteLine("     - Restructures SDC files with the format (beta)$live(2)$SceneName$SceneFileName.sdc to CDN structure.");
    }
}