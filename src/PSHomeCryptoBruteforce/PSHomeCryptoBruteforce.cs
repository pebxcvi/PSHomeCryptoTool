using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

class PSHomeCryptoBruteforce
{
    private static bool DebugEnabled = false;

    private static readonly HashSet<string> SupportedExtensions =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".sdc",
            ".odc",
            ".hcdb",
            ".xml",
            ".bar"
        };

    private sealed class ToolConfig
    {
        public string OutputPath { get; set; } = string.Empty;
        public bool Debug { get; set; } = false;
        public int Threads { get; set; } = 0;
        public ushort CdnMode { get; set; } = 0;
        public bool PauseOnExit { get; set; } = true;
        public bool CleanFolders { get; set; } = true;
        public bool WriteSha1Log { get; set; } = true;
        public bool AppendSha1 { get; set; } = false;
        public bool OdcRename { get; set; } = false;
        public bool SdcRename { get; set; } = false;
        public bool HCDBBruteforceShortcut { get; set; } = true;
        public bool HCDBDecompress { get; set; } = true;
        public int HCDBBruteforceTimeout { get; set; } = 180;
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
    }

    private sealed class OutputInfo
    {
        public string OutputFilePath { get; set; } = string.Empty;
        public string BucketRootPath { get; set; } = string.Empty;
        public string RelativePathInsideBucket { get; set; } = string.Empty;
        public string RelativeInputPath { get; set; } = string.Empty;
        public string Sha1ForLog { get; set; } = string.Empty;
    }

    static int Main(string[] args)
    {
        int exitCode = 0;
        bool pauseOnExit = true;
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            string exeDir = AppContext.BaseDirectory;
            string configPath = Path.Combine(exeDir, "config-bruteforce.ini");
            
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
            ushort? cliCdnMode = null;
            bool? cliPauseOnExit = null;
            bool? cliCleanFolders = null;
            bool? cliWriteSha1Log = null;
            bool? cliAppendSha1 = null;
            bool? cliOdcRename = null;
            bool? cliSdcRename = null;
            bool? cliHCDBBruteforceShortcut = null;
            bool? cliHCDBDecompress = null;
            int? cliHCDBBruteforceTimeout = null;

            ParseArgs(
                args,
                inputPaths,
                ref cliOutputPath,
                ref cliDebug,
                ref cliThreads,
                ref cliCdnMode,
                ref cliPauseOnExit,
                ref cliCleanFolders,
                ref cliWriteSha1Log,
                ref cliAppendSha1,
                ref cliOdcRename,
                ref cliSdcRename,
                ref cliHCDBBruteforceShortcut,
                ref cliHCDBDecompress,
                ref cliHCDBBruteforceTimeout
            );

            string effectiveOutputPath = !string.IsNullOrWhiteSpace(cliOutputPath)
                ? CleanOutputPath(cliOutputPath)
                : CleanOutputPath(config.OutputPath ?? string.Empty);

            DebugEnabled = cliDebug ?? config.Debug;
            int effectiveThreads = cliThreads ?? config.Threads;
            ushort effectiveCdnMode = cliCdnMode ?? config.CdnMode;
            pauseOnExit = cliPauseOnExit ?? config.PauseOnExit;
            bool cleanFolders = cliCleanFolders ?? config.CleanFolders;
            bool writeSha1Log = cliWriteSha1Log ?? config.WriteSha1Log;
            bool effectiveAppendSha1 = cliAppendSha1 ?? config.AppendSha1;
            bool effectiveOdcRename = cliOdcRename ?? config.OdcRename;
            bool effectiveSdcRename = cliSdcRename ?? config.SdcRename;
            bool effectiveHCDBBruteforceShortcut = cliHCDBBruteforceShortcut ?? config.HCDBBruteforceShortcut;
            bool effectiveHCDBDecompress = cliHCDBDecompress ?? config.HCDBDecompress;
            int effectiveHCDBBruteforceTimeout = Math.Max(0, cliHCDBBruteforceTimeout ?? config.HCDBBruteforceTimeout);

            ThreadLimiter.ThreadLimitMode = effectiveThreads;
            CTRExploitProcess.UseHCDBBruteforceShortcut = effectiveHCDBBruteforceShortcut;


            if (inputPaths.Count == 0)
            {
                PrintUsage();
                return 1;
            }

            List<InputFileItem> filesToProcess = ExpandInputPaths(inputPaths);

            if (filesToProcess.Count == 0)
            {
                Console.WriteLine();
                Console.WriteLine("ERROR : ");
                Console.WriteLine();
                Console.WriteLine("    No supported files found to process.");
                return 1;
            }

            string outputRoot = !string.IsNullOrWhiteSpace(effectiveOutputPath)
                ? Path.GetFullPath(effectiveOutputPath)
                : Path.Combine(exeDir, "Decrypted");

            if (cleanFolders)
                CleanBucketFolders(outputRoot, filesToProcess);

            DebugLog($"Executable directory: {exeDir}");
            DebugLog($"Config path: {configPath}");
            DebugLog($"CLI args count: {args.Length}");
            DebugLog($"Effective outputpath: {effectiveOutputPath}");
            DebugLog($"Effective debug: {DebugEnabled}");
            DebugLog($"Effective threads mode: {effectiveThreads}");
            DebugLog($"Effective threads resolved: {ThreadLimiter.NumOfThreadsAvailable}");
            DebugLog($"Effective cdnmode: {effectiveCdnMode}");
            DebugLog($"Pause on exit: {pauseOnExit}");
            DebugLog($"Clean ext folders: {cleanFolders}");
            DebugLog($"WriteSha1Log: {writeSha1Log}");
            DebugLog($"AppendSha1: {effectiveAppendSha1}");
            DebugLog($"OdcRename: {effectiveOdcRename}");
            DebugLog($"SdcRename: {effectiveSdcRename}");
            DebugLog($"HCDBBruteforceShortcut: {effectiveHCDBBruteforceShortcut}");
            DebugLog($"HCDBDecompress: {effectiveHCDBDecompress}");
            DebugLog($"HCDBBruteforceTimeout: {effectiveHCDBBruteforceTimeout}");
            DebugLog($"Output root: {outputRoot}");
            DebugLog($"Supported files found: {filesToProcess.Count}");

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

                    processedCount++;
                    string progressLabel = $"[{processedCount}/{filesToProcess.Count}]";

                    Console.WriteLine($"{progressLabel} {inputItem.DisplayInputPath}");

                    PSHomeBruteforce.CurrentPrefix = progressLabel;
                    PSHomeBruteforce.StatusDebugEnabled = DebugEnabled;

                    OutputInfo outputInfo = ProcessSingleFile(
                        inputItem,
                        outputRoot,
                        effectiveCdnMode,
                        effectiveHCDBDecompress,
                        effectiveAppendSha1,
                        effectiveOdcRename,
                        effectiveSdcRename,
                        effectiveHCDBBruteforceTimeout
                    );

                    if (outputInfo.OutputFilePath == null)
                    {
                        PSHomeBruteforce.PrintErrorStatus("Bruteforce Failed!");
                        failCount++;
                        continue;
                    }

                    if (writeSha1Log)
                    {
                        AppendSha1Log(
                            outputInfo.BucketRootPath,
                            outputInfo.RelativePathInsideBucket,
                            outputInfo.Sha1ForLog
                        );
                        DebugLog($"{progressLabel} SHA1 log updated.");
                    }

                    successCount++;
                }
                catch (Exception ex)
                {
                    failCount++;

                    PSHomeBruteforce.PrintErrorStatus("Bruteforce Failed!");

                    if (DebugEnabled)
                        Console.WriteLine(ex.ToString());
                }
                finally
                {
                    PSHomeBruteforce.CurrentPrefix = string.Empty;
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

    private static OutputInfo ProcessSingleFile(
        InputFileItem inputItem,
        string outputRoot,
        ushort cdnMode,
        bool hcdbDecompress,
        bool appendSha1,
        bool odcRename,
        bool sdcRename,
        int HCDBbruteforceTimeout)
    {
        DebugLog($"Reading: {inputItem.FullPath}");

        byte[] buffer = File.ReadAllBytes(inputItem.FullPath);

        PSHomeBruteforce proc = new PSHomeBruteforce(buffer);
        int mode = GetBruteforceMode(inputItem.Extension);

        DebugLog($"Bruteforce mode: {mode}");
        DebugLog($"cdnMode: {cdnMode}");

        PSHomeBruteforce.PrintStatus("Bruteforcing ...");
        byte[] result = proc.StartBruteForce(cdnMode, mode, HCDBbruteforceTimeout);

        if (result == null)
        {
            return new OutputInfo
            {
                OutputFilePath = null,
                BucketRootPath = string.Empty,
                RelativePathInsideBucket = string.Empty,
                RelativeInputPath = inputItem.DisplayInputPath,
                Sha1ForLog = string.Empty
            };
        }

        PSHomeBruteforce.PrintStatus("Bruteforce Successful!");

        byte[] outputBytes = result;
        string outputFileName = inputItem.FileName;
        string sha1ForLog = DotNetHasher.ComputeSHA1String(result);

        if (inputItem.Extension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase))
        {
            string baseName = Path.GetFileNameWithoutExtension(inputItem.FileName);
            string appendSha1Suffix = ShouldAppendSha1(inputItem, appendSha1)
                ? "_" + sha1ForLog.ToLowerInvariant()
                : string.Empty;

            if (hcdbDecompress)
            {
                PSHomeBruteforce.PrintStatus("Decompressing ...");

                byte[] decompressedData = LZMASegsDecompressor.SegmentsDecompress(result, false);
                if (decompressedData != null)
                {
                    outputBytes = decompressedData;
                    outputFileName = baseName + appendSha1Suffix + ".sql";
                    PSHomeBruteforce.PrintStatus("Decompression Successful!");
                }
                else
                {
                    outputFileName = baseName + appendSha1Suffix + ".sql";
                    PSHomeBruteforce.PrintErrorStatus("Decompression Failed!");
                }
            }
            else
            {
                outputFileName = baseName + appendSha1Suffix + ".sql";
                PSHomeBruteforce.PrintStatus("Skipping Decompression ...");
            }
        }
        else
        {
            if (ShouldAppendSha1(inputItem, appendSha1))
            {
                string baseName = Path.GetFileNameWithoutExtension(inputItem.FileName);
                string ext = Path.GetExtension(inputItem.FileName);
                outputFileName = baseName + "_" + sha1ForLog.ToLowerInvariant() + ext;
            }
        }

        string relativeOutputPath = GetOutputRelativePath(
            inputItem,
            outputFileName,
            odcRename,
            sdcRename
        );

        string bucketName = GetBucketNameFromOutputRelativePath(relativeOutputPath);
        string pathInsideBucket = RemoveLeadingBucketFolder(relativeOutputPath, bucketName);

        string bucketRootPath = Path.Combine(outputRoot, bucketName);
        string outputFilePath = Path.Combine(bucketRootPath, pathInsideBucket);
        string outputFolderPath = Path.GetDirectoryName(outputFilePath) ?? bucketRootPath;

        Directory.CreateDirectory(outputRoot);
        Directory.CreateDirectory(outputFolderPath);

        DebugLog($"Writing: {outputFilePath}");
        File.WriteAllBytes(outputFilePath, outputBytes);

        return new OutputInfo
        {
            OutputFilePath = outputFilePath,
            BucketRootPath = bucketRootPath,
            RelativePathInsideBucket = NormalizePath(pathInsideBucket),
            RelativeInputPath = inputItem.DisplayInputPath,
            Sha1ForLog = sha1ForLog
        };
    }

    private static bool ShouldAppendSha1(InputFileItem inputItem, bool appendSha1)
    {
        if (!appendSha1)
            return false;

        if (inputItem.Extension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase))
            return true;

        if (inputItem.Extension.Equals(".bar", StringComparison.OrdinalIgnoreCase))
            return true;

        if (inputItem.Extension.Equals(".xml", StringComparison.OrdinalIgnoreCase))
        {
            if (inputItem.FileName.IndexOf("Scenelist_", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;

            if (inputItem.FileName.IndexOf("Navigator_", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }

        return false;
    }

    private static void AppendSha1Log(string bucketRootPath, string relativePathInsideBucket, string sha1)
    {
        string logPath = Path.Combine(bucketRootPath, "sha1_hashes.txt");

        using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read))
        using (StreamWriter writer = new StreamWriter(fs, new UTF8Encoding(false)))
        {
            if (fs.Length == 0)
                writer.WriteLine("File\tSHA1");

            writer.WriteLine($"{NormalizePath(relativePathInsideBucket)}\t{sha1}");
        }
    }

    private static int GetBruteforceMode(string extension)
    {
        if (extension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase))
            return 1;

        if (extension.Equals(".bar", StringComparison.OrdinalIgnoreCase))
            return 2;

        return 0;
    }

    private static string GetOutputRelativePath(
        InputFileItem inputItem,
        string outputFileName,
        bool odcRename,
        bool sdcRename)
    {
        string bucketName = inputItem.Extension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase)
            ? "SQL"
            : inputItem.Extension.TrimStart('.').ToUpperInvariant();

        string hostPrefix = string.Empty;
    
        if (inputItem.InputHadSubfolders &&
            !string.IsNullOrWhiteSpace(inputItem.InputRootFolderName))
        {
            hostPrefix = inputItem.InputRootFolderName;
        }
    
        if (odcRename &&
            inputItem.Extension.Equals(".odc", StringComparison.OrdinalIgnoreCase) &&
            inputItem.InputHadSubfolders)
        {
            string? renamedOdc = TryBuildFlattenedOdcName(inputItem);
            if (!string.IsNullOrEmpty(renamedOdc))
                return Path.Combine(bucketName, renamedOdc);
        }
    
        if (sdcRename &&
            inputItem.Extension.Equals(".sdc", StringComparison.OrdinalIgnoreCase) &&
            inputItem.InputHadSubfolders)
        {
            string? renamedSdc = TryBuildFlattenedSdcName(inputItem);
            if (!string.IsNullOrEmpty(renamedSdc))
                return Path.Combine(bucketName, renamedSdc);
        }
    
        string dir = Path.GetDirectoryName(inputItem.RelativePathWithoutTopFolder) ?? string.Empty;
    
        if (string.IsNullOrEmpty(dir))
        {
            if (string.IsNullOrEmpty(hostPrefix))
                return Path.Combine(bucketName, outputFileName);
    
            return Path.Combine(bucketName, hostPrefix, outputFileName);
        }
    
        if (string.IsNullOrEmpty(hostPrefix))
            return Path.Combine(bucketName, dir, outputFileName);
    
        return Path.Combine(bucketName, hostPrefix, dir, outputFileName);
    }

    private static string? TryGetCdnPathFromFullPath(InputFileItem inputItem, string wantedFolder)
    {
        string normalized = NormalizePath(inputItem.FullPath);
        string[] parts = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
    
        int hostIndex = -1;
    
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].EndsWith(".playstation.net", StringComparison.OrdinalIgnoreCase))
            {
                hostIndex = i;
                break;
            }
        }
    
        if (hostIndex < 0)
            return null;
    
        if (hostIndex + 6 >= parts.Length)
            return null;
    
        if (!parts[hostIndex + 1].Equals("c.home", StringComparison.OrdinalIgnoreCase))
            return null;
    
        string environmentSegment = parts[hostIndex + 2];
        string liveToken = parts[hostIndex + 3];
        string folderSegment = parts[hostIndex + 4];
    
        if (!folderSegment.Equals(wantedFolder, StringComparison.OrdinalIgnoreCase))
            return null;
    
        if (!environmentSegment.Equals("prod", StringComparison.OrdinalIgnoreCase) &&
            !environmentSegment.Equals("prod2", StringComparison.OrdinalIgnoreCase) &&
            !environmentSegment.Equals("beta", StringComparison.OrdinalIgnoreCase))
            return null;
    
        if (!liveToken.Equals("live", StringComparison.OrdinalIgnoreCase) &&
            !liveToken.Equals("live2", StringComparison.OrdinalIgnoreCase))
            return null;
    
        return string.Join("\\", parts, hostIndex, parts.Length - hostIndex);
    }
    
    private static string? TryBuildFlattenedOdcName(InputFileItem inputItem)
    {
        string normalized = NormalizePath(
            string.IsNullOrEmpty(inputItem.InputRootFolderName)
                ? inputItem.RelativePathWithoutTopFolder
                : Path.Combine(inputItem.InputRootFolderName, inputItem.RelativePathWithoutTopFolder)
        );
    
        if (!normalized.Contains(@"\c.home\", StringComparison.OrdinalIgnoreCase))
        {
            string? fullPathNormalized = TryGetCdnPathFromFullPath(inputItem, "Objects");
            if (!string.IsNullOrEmpty(fullPathNormalized))
                normalized = fullPathNormalized;
        }
    
        bool hasAllowedPrefix =
            normalized.StartsWith(@"scee-home.playstation.net\c.home\prod\live\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"scee-home.playstation.net\c.home\prod2\live2\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"scee-home.playstation.net\c.home\beta\live\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"scee-home.playstation.net\c.home\beta\live2\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\prod\live\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\prod2\live2\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\beta\live\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\beta\live2\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"prod\live\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"prod2\live2\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"beta\live\Objects\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"beta\live2\Objects\", StringComparison.OrdinalIgnoreCase);
    
        if (!hasAllowedPrefix)
            return null;
    
        string[] parts = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
    
        int baseIndex;
        if (parts[0].Equals("scee-home.playstation.net", StringComparison.OrdinalIgnoreCase))
            baseIndex = 1;
        else if (parts[0].Equals("c.home", StringComparison.OrdinalIgnoreCase))
            baseIndex = 0;
        else
            baseIndex = -1;
    
        string environmentSegment;
        string liveToken;
        string objectsSegment;
        string uuid;
        string fileName;
    
        if (baseIndex == 1)
        {
            environmentSegment = parts[2];
            liveToken = parts[3];
            objectsSegment = parts[4];
            uuid = parts[5];
            fileName = parts[6];
        }
        else if (baseIndex == 0)
        {
            environmentSegment = parts[1];
            liveToken = parts[2];
            objectsSegment = parts[3];
            uuid = parts[4];
            fileName = parts[5];
        }
        else
        {
            environmentSegment = parts[0];
            liveToken = parts[1];
            objectsSegment = parts[2];
            uuid = parts[3];
            fileName = parts[4];
        }
    
        if (!objectsSegment.Equals("Objects", StringComparison.OrdinalIgnoreCase))
            return null;
    
        bool isBeta;
        if (environmentSegment.Equals("beta", StringComparison.OrdinalIgnoreCase))
        {
            isBeta = true;
        }
        else if (environmentSegment.Equals("prod", StringComparison.OrdinalIgnoreCase) ||
                 environmentSegment.Equals("prod2", StringComparison.OrdinalIgnoreCase))
        {
            isBeta = false;
        }
        else
        {
            return null;
        }
    
        if (!liveToken.Equals("live", StringComparison.OrdinalIgnoreCase) &&
            !liveToken.Equals("live2", StringComparison.OrdinalIgnoreCase))
            return null;
    
        string tValue;
    
        if (fileName.Equals("object.odc", StringComparison.OrdinalIgnoreCase))
        {
            tValue = "000";
        }
        else
        {
            string fileNameNoExt = Path.GetFileNameWithoutExtension(fileName);
            if (!fileNameNoExt.StartsWith("object_T", StringComparison.OrdinalIgnoreCase))
                return null;
    
            string extracted = fileNameNoExt.Substring(8);
            if (extracted.Length != 3)
                return null;
    
            tValue = extracted;
        }
    
        string prefix = isBeta ? "beta$" : string.Empty;
        return $"{prefix}{liveToken}${uuid}_T{tValue}.odc";
    }
           
    private static string? TryBuildFlattenedSdcName(InputFileItem inputItem)
    {
        string normalized = NormalizePath(
            string.IsNullOrEmpty(inputItem.InputRootFolderName)
                ? inputItem.RelativePathWithoutTopFolder
                : Path.Combine(inputItem.InputRootFolderName, inputItem.RelativePathWithoutTopFolder)
        );
    
        if (!normalized.Contains(@"\c.home\", StringComparison.OrdinalIgnoreCase))
        {
            string? fullPathNormalized = TryGetCdnPathFromFullPath(inputItem, "Scenes");
            if (!string.IsNullOrEmpty(fullPathNormalized))
                normalized = fullPathNormalized;
        }
    
        bool hasAllowedPrefix =
            normalized.StartsWith(@"scee-home.playstation.net\c.home\prod\live\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"scee-home.playstation.net\c.home\prod2\live2\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"scee-home.playstation.net\c.home\beta\live\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"scee-home.playstation.net\c.home\beta\live2\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\prod\live\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\prod2\live2\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\beta\live\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"c.home\beta\live2\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"prod\live\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"prod2\live2\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"beta\live\Scenes\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"beta\live2\Scenes\", StringComparison.OrdinalIgnoreCase);
    
        if (!hasAllowedPrefix)
            return null;
    
        string[] parts = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
    
        int baseIndex;
        if (parts[0].Equals("scee-home.playstation.net", StringComparison.OrdinalIgnoreCase))
            baseIndex = 1;
        else if (parts[0].Equals("c.home", StringComparison.OrdinalIgnoreCase))
            baseIndex = 0;
        else
            baseIndex = -1; // prod/prod2/beta directly
    
        string environmentSegment;
        string liveToken;
        string scenesSegment;
        string sceneName;
        string sceneFileName;
    
        if (baseIndex == 1)
        {
            environmentSegment = parts[2];
            liveToken = parts[3];
            scenesSegment = parts[4];
            sceneName = parts[5];
            sceneFileName = parts[6];
        }
        else if (baseIndex == 0)
        {
            environmentSegment = parts[1];
            liveToken = parts[2];
            scenesSegment = parts[3];
            sceneName = parts[4];
            sceneFileName = parts[5];
        }
        else
        {
            environmentSegment = parts[0];
            liveToken = parts[1];
            scenesSegment = parts[2];
            sceneName = parts[3];
            sceneFileName = parts[4];
        }
    
        if (!scenesSegment.Equals("Scenes", StringComparison.OrdinalIgnoreCase))
            return null;
    
        bool isBeta;
        if (environmentSegment.Equals("beta", StringComparison.OrdinalIgnoreCase))
        {
            isBeta = true;
        }
        else if (environmentSegment.Equals("prod", StringComparison.OrdinalIgnoreCase) ||
                 environmentSegment.Equals("prod2", StringComparison.OrdinalIgnoreCase))
        {
            isBeta = false;
        }
        else
        {
            return null;
        }
    
        if (!liveToken.Equals("live", StringComparison.OrdinalIgnoreCase) &&
            !liveToken.Equals("live2", StringComparison.OrdinalIgnoreCase))
            return null;
    
        string prefix = isBeta ? "beta$" : string.Empty;
        return $"{prefix}{liveToken}${sceneName}${sceneFileName}";
    }

    private static void CleanBucketFolders(string outputRoot, List<InputFileItem> filesToProcess)
    {
        HashSet<string> bucketNamesToClean = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (InputFileItem item in filesToProcess)
        {
            if (!IsSupportedExtension(item.Extension))
                continue;

            string bucketName = item.Extension.Equals(".hcdb", StringComparison.OrdinalIgnoreCase)
                ? "SQL"
                : item.Extension.TrimStart('.').ToUpperInvariant();

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

   private static List<InputFileItem> ExpandInputPaths(List<string> inputPaths)
   {
       List<InputFileItem> results = new List<InputFileItem>(Math.Max(inputPaths.Count, 16));
   
       foreach (string path in inputPaths)
       {
           if (string.IsNullOrWhiteSpace(path))
               continue;
   
           if (File.Exists(path))
           {
               string fullPath = Path.GetFullPath(path);
               string ext = Path.GetExtension(fullPath);
   
               if (!IsSupportedExtension(ext))
               {
                   DebugLog($"Ignoring unsupported file: {path}");
                   continue;
               }
   
               string fileName = Path.GetFileName(fullPath);
   
               InputFileItem item = new InputFileItem
               {
                   FullPath = fullPath,
                   RelativePathWithoutTopFolder = fileName,
                   InputRootFolderName = string.Empty,
                   InputHadSubfolders = false,
                   Extension = ext,
                   FileName = fileName
               };
   
               item.DisplayInputPath = BuildDisplayInputPath(item);
               results.Add(item);
           }
           else if (Directory.Exists(path))
           {
               string rootPath = Path.GetFullPath(path);
               string rootFolderName = Path.GetFileName(rootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
   
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
   
                   item.DisplayInputPath = BuildDisplayInputPath(item);
                   results.Add(item);
               }
           }
       }
   
       return results;
   }

    private static bool IsSupportedExtension(string ext)
    {
        return SupportedExtensions.Contains(ext);
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
    
    private static string BuildDisplayInputPath(InputFileItem inputItem)
    {
        if (!inputItem.InputHadSubfolders || string.IsNullOrWhiteSpace(inputItem.InputRootFolderName))
            return NormalizePath(inputItem.RelativePathWithoutTopFolder);
    
        return NormalizePath(Path.Combine(inputItem.InputRootFolderName, inputItem.RelativePathWithoutTopFolder));
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
        ref ushort? cliCdnMode,
        ref bool? cliPauseOnExit,
        ref bool? cliCleanFolders,
        ref bool? cliWriteSha1Log,
        ref bool? cliAppendSha1,
        ref bool? cliOdcRename,
        ref bool? cliSdcRename,
        ref bool? cliHCDBBruteforceShortcut,
        ref bool? cliHCDBDecompress,
        ref int? cliHCDBBruteforceTimeout)
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

            if (arg.Equals("-appendsha1", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/appendsha1", StringComparison.OrdinalIgnoreCase))
            {
                cliAppendSha1 = true;
                continue;
            }

            if (arg.Equals("-noappendsha1", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/noappendsha1", StringComparison.OrdinalIgnoreCase))
            {
                cliAppendSha1 = false;
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

            if (arg.Equals("-hcdbbruteforceshortcut", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbbruteforceshortcut", StringComparison.OrdinalIgnoreCase))
            {
                cliHCDBBruteforceShortcut = true;
                continue;
            }

            if (arg.Equals("-nohcdbbruteforceshortcut", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nohcdbbruteforceshortcut", StringComparison.OrdinalIgnoreCase))
            {
                cliHCDBBruteforceShortcut = false;
                continue;
            }

            if (arg.Equals("-hcdbdecompress", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbdecompress", StringComparison.OrdinalIgnoreCase))
            {
                cliHCDBDecompress = true;
                continue;
            }

            if (arg.Equals("-nohcdbdecompress", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/nohcdbdecompress", StringComparison.OrdinalIgnoreCase))
            {
                cliHCDBDecompress = false;
                continue;
            }
            
            if (arg.Equals("-hcdbbruteforcetimeout", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbbruteforcetimeout", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("-hcdbtimeout", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/hcdbtimeout", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length && int.TryParse(args[++i], out int parsedHCDBBruteforceTimeout))
                    cliHCDBBruteforceTimeout = Math.Max(0, parsedHCDBBruteforceTimeout);
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
        sb.AppendLine("appendsha1=false");
        sb.AppendLine("; ");
        sb.AppendLine("; - Appends SHA1 to output filenames for HCDB/BAR/Scenelist/Navigator.");
        sb.AppendLine("; ");
        sb.AppendLine("odcrename=false");
        sb.AppendLine("; ");
        sb.AppendLine("; - Flattens ODC paths to (beta)$live(2)$UUID_TXXX.odc");
        sb.AppendLine("; ");
        sb.AppendLine("sdcrename=false");
        sb.AppendLine("; ");
        sb.AppendLine("; - Flattens SDC paths to (beta)$live(2)$SceneName$SceneFileName.sdc");
        sb.AppendLine("; ");
        sb.AppendLine("hcdbbruteforceshortcut=true");
        sb.AppendLine("hcdbdecompress=true");
        sb.AppendLine("hcdbbruteforcetimeout=180");
        sb.AppendLine("; ");
        sb.AppendLine("; - HCDB Bruteforce timeout in seconds.");
        sb.AppendLine(";     0 = no timeout");
        sb.AppendLine(";     60 = 1 minute");
        sb.AppendLine(";     120 = 2 minutes");
        sb.AppendLine(";     180 = 3 minutes");
        sb.AppendLine(";     240 = 4 minutes");
        sb.AppendLine(";     300 = 5 minutes");

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
                if (TryParseBool(value, out bool parsedWriteSha1Log))
                    config.WriteSha1Log = parsedWriteSha1Log;
            }
            else if (key.Equals("appendsha1", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedAppendSha1))
                    config.AppendSha1 = parsedAppendSha1;
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
            else if (key.Equals("hcdbbruteforceshortcut", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedShortcut))
                    config.HCDBBruteforceShortcut = parsedShortcut;
            }
            else if (key.Equals("hcdbdecompress", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseBool(value, out bool parsedHCDBDecompress))
                    config.HCDBDecompress = parsedHCDBDecompress;
            }
            else if (key.Equals("hcdbbruteforcetimeout", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(value, out int parsedHCDBBruteforceTimeout))
                    config.HCDBBruteforceTimeout = Math.Max(0, parsedHCDBBruteforceTimeout);
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
        if (DebugEnabled)
            Console.WriteLine("[DEBUG] " + message);
    }

    private static void PauseIfNeeded(bool pauseOnExit)
    {
        if (!pauseOnExit)
            return;

        Console.WriteLine();
        Console.WriteLine("Press any key to close...");
        Console.ReadKey(true);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("PSHomeCryptoBruteforce");
        Console.WriteLine();
        Console.WriteLine("Supported extensions: .sdc .odc .hcdb .xml .bar");
        Console.WriteLine("Drag and drop files and/or folders onto the EXE");
        Console.WriteLine("or use:");
        Console.WriteLine();
        Console.WriteLine("  PSHomeCryptoBruteforce.exe [files/folders...]");
        Console.WriteLine("   [-outputpath PATH]");
        Console.WriteLine("   [-debug]");
        Console.WriteLine("   [-threads -2|-1|0|1|2+]");
        Console.WriteLine("   [-cdnmode 0|1|2]");
        Console.WriteLine("   [-pause|-nopause]");
        Console.WriteLine("   [-cleanfolders|-nocleanfolders]");
        Console.WriteLine("   [-sha1log|-nosha1log]");
        Console.WriteLine("   [-appendsha1|-noappendsha1]");
        Console.WriteLine("   [-odcrename|-noodcrename]");
        Console.WriteLine("   [-sdcrename|-nosdcrename]");
        Console.WriteLine("   [-hcdbbruteforceshortcut|-nohcdbbruteforceshortcut]");
        Console.WriteLine("   [-hcdbdecompress|-nohcdbdecompress]");
        Console.WriteLine("   [-hcdbbruteforcetimeout SECONDS]");
        Console.WriteLine();
        Console.WriteLine("config-bruteforce.ini:");
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
        Console.WriteLine("  appendsha1=false");
        Console.WriteLine("     - Appends SHA1 to output filenames for HCDB/BAR/Scenelist/Navigator.");
        Console.WriteLine();
        Console.WriteLine("  odcrename=false");
        Console.WriteLine("     - Flattens ODC paths to (beta)$live(2)$UUID_TXXX.odc");
        Console.WriteLine();
        Console.WriteLine("  sdcrename=false");
        Console.WriteLine("     - Flattens SDC paths to (beta)$live(2)$SceneName$SceneFileName.sdc");
        Console.WriteLine();
        Console.WriteLine("  hcdbbruteforceshortcut=true");
        Console.WriteLine("  hcdbdecompress=true");
        Console.WriteLine("  hcdbbruteforcetimeout=180");
        Console.WriteLine("     - HCDB Bruteforce timeout in seconds.");
        Console.WriteLine("         0 = no timeout");
        Console.WriteLine("         60 = 1 minute");
        Console.WriteLine("         120 = 2 minutes");
        Console.WriteLine("         180 = 3 minutes");
        Console.WriteLine("         240 = 4 minutes");
        Console.WriteLine("         300 = 5 minutes");
    }
}