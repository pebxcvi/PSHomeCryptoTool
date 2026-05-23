# PSHomeCryptoTool
## PlayStation®Home Crypto Tool
...

> [!IMPORTANT]
> Download Release -> https://github.com/pebxcvi/PSHomeCryptoTool/releases/tag/V1.0

...

> [!NOTE]
> This toolset was put together with assistance from AI ( ChatGPT Plus ).
>
> This toolset was built then tested only on Windows x64/x86 operating systems. There will be no plans to debug/test on Linux or macOS.

...

## Overview
The purpose of the PlayStation®Home Crypto Tool is to decrypt or encrypt a specific subset of data files used within a PlayStation®Home CDN ( Content Delivery Network ).

They play an important role in serving and maintaining content on a PlayStation®Home server. If you were to have a PlayStation®Home server, you'll most likely be working with them on a daily basis.

They can commonly be found within PlayStation®Home data caches and are limited to the following :

```
SceneList XMLs
Object descriptor files ( ODC )
Scene descriptor files ( SDC )
Object Catalogue HCDB files ( Compressed SQLite database )
Object Catalogue BAR Archives ( With XML inside )
DefaultInventory BAR Archives ( With XML inside )
DynamicLocalisation XMLs
Navigator XMLs
```

For more information on caches ->

https://github.com/pebxcvi/PSHomeCacheDepot#-cache-overview-

https://github.com/pebxcvi/PSHomeCacheExtractor/tree/main#cache-breakdown


## Usage

The PlayStation®Home Crypto Tool is split into two executables :

1) PSHomeCryptoBruteforce.exe
    - This is the decrypter but technically is a bruteforcer since the SHA1 hashes of the files are unknown. It utilizes a custom method found within ```/src/PSHomeCryptoTool/CTRExploitProcess.cs``` that makes bruteforcing a breeze.
      
    - For the HCDB Object Catalogues, it will automatically decompress the SQLite databases after bruteforcing.
  
2) PSHomeCryptoEncrypt.exe
    - This is the encrypter that encrypts the files using their SHA1 Hashes.
      
    - For the HCDB Object Catalogues, it will automatically compress the SQLite databases before encryption and if already compressed, skip and continue on to encryption. The compression is a C# reimplementation of a LMZA Segs Compressor sample found in one of Sony's PS3 SDKs that heavily utilizes 7-Zip's LMZA C# Library.

For more information on the types of encryption -> https://github.com/pebxcvi/PSHomeCacheExtractor/tree/main#encryption-overview

...

There are two ways to use this toolset. You can either ...

### Drag and Drop

1) Drag and drop folders or files ontop of the compiled executables.
   
    - When running either executable for the first time, it will automatically generate a configuration `.ini` file beside it. Each configuration file contains detailed comments explaining the available settings and options.

**config-bruteforce.ini**
```
outputpath=
debug=false
threads=0
 -2 = RPCS3-aware auto
     If rpcs3 is running, use a lighter automatic limit.
     Otherwise use normal auto.
 -1 = Full CPU
     Uses Environment.ProcessorCount exactly.
     Example: if system reports 24 logical processors, use 24.
 0 = Auto balanced
     Uses a conservative automatic value so CPU is not overkilled.
     Current rule: half of logical processors, minimum 1.
     Example: 24 -> 12, 8 -> 4, 1 -> 1.
 1 = Force 1 thread
     Lowest manual setting.
 2+ = Force exact manual thread count
     Example: 4 = use 4 threads, 8 = use 8 threads.
cdnmode=0
  0 = Default / Retail Blowfish key
  1 = Beta Blowfish key
  2 = HDK Blowfish key
pauseonexit=true
cleanfolders=true
sha1log=true
  - Writes sha1_hashes.txt in each output bucket.
appendsha1=false
  - Appends SHA1 to output filenames for HCDB/BAR/Scenelist/Navigator.
 odcrename=false
  - Flattens ODC paths to (beta)$live(2)$UUID_TXXX.odc
sdcrename=false
  - Flattens SDC paths to (beta)$live(2)$SceneName$SceneFileName.sdc
hcdbbruteforceshortcut=true
hcdbdecompress=true
hcdbbruteforcetimeout=180
  - HCDB Bruteforce timeout in seconds.
  0 = no timeout
  60 = 1 minute
  120 = 2 minutes
  180 = 3 minutes
  240 = 4 minutes
  300 = 5 minutes
```
**config-encrypt.ini**
```
outputpath=
debug=false
threads=0
 -2 = RPCS3-aware auto
     If rpcs3 is running, use a lighter automatic limit.
     Otherwise use normal auto.
 -1 = Full CPU
     Uses Environment.ProcessorCount exactly.
     Example: if system reports 24 logical processors, use 24.
 0 = Auto balanced
     Uses a conservative automatic value so CPU is not overkilled.
     Current rule: half of logical processors, minimum 1.
     Example: 24 -> 12, 8 -> 4, 1 -> 1.
 1 = Force 1 thread
     Lowest manual setting.
 2+ = Force exact manual thread count
     Example: 4 = use 4 threads, 8 = use 8 threads.
sha1=
  - Manual SHA1 input : Only works when processing one file.
  - Used for decrypting when the file's SHA1 is already known.
  - For multiple files, PSHomeCryptoBruteforce is recommended.
hcdbdecompress=true
  - Used in conjunction with manual SHA1 input : If SQL/HCDB, decompresses from segs to SQLite.
hcdbcompresslevel=9
  - HCDB compression level used when compressing SQLite to segs.
hcdbcompressmaxsize=65536
  - HCDB segment size used when compressing SQLite to segs.
cdnmode=0
  0 = Default / Retail Blowfish key
  1 = Beta Blowfish key
  2 = HDK Blowfish key
pauseonexit=true
cleanfolders=true
sha1log=true
  - Writes sha1_hashes.txt in each output bucket.
odcrename=false
  - Restructures ODC files with the format (beta)$live(2)$UUID_TXXX.odc to CDN structure.
sdcrename=false
  - Restructures SDC files with the format (beta)$live(2)$SceneName$SceneFileName.sdc to CDN structure.
  ```

### Command Line

2) Use it in the command line directly or via Windows batch scripts.

    - When using the command line for either executable, it does not load or rely on the configuration `.ini` file and instead operates entirely from the provided command-line parameters.

```
  PSHomeCryptoBruteforce.exe [files/folders...]
      [-outputpath PATH]
      [-debug]
      [-threads -1|0|1+]
      [-cdnmode 0|1|2]
      [-pause|-nopause]
      [-cleanfolders|-nocleanfolders]
      [-sha1log|-nosha1log]
      [-appendsha1|-noappendsha1]
      [-odcrename|-noodcrename]
      [-sdcrename|-nosdcrename]
      [-hcdbbruteforceshortcut|-nohcdbbruteforceshortcut]
      [-hcdbdecompress|-nohcdbdecompress]
      [-hcdbbruteforcetimeout SECONDS]
```
```
  PSHomeCryptoEncrypt.exe [files/folders...]
      [-outputpath PATH]
      [-debug]
      [-threads -2|-1|0|1+]
      [-sha1 HEX]
      [-hcdbdecompress|-nohcdbdecompress]
      [-hcdbcompresslevel N]
      [-hcdbcompressmaxsize N]
      [-cdnmode 0|1|2]
      [-pause|-nopause]
      [-cleanfolders|-nocleanfolders]
      [-sha1log]
      [-odcrename|-noodcrename]
      [-sdcrename|-nosdcrename]
```
## Components

The PlayStation®Home Crypto Tool uses Net 6 
- https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-6.0.428-windows-x64-installer

... and utilities the following C# projects :

NautilusXP2024 -> https://github.com/GitHubProUser67/NautilusXP2024 
- The C# found in ```/src/PSHomeCryptoTool/``` comes directly from there. 

BouncyCastle -> https://github.com/bcgit/bc-csharp

SharpCompress -> https://github.com/adamhathcock/sharpcompress

LZMA-SDK -> https://github.com/welovegit/LZMA-SDK

## Mentions

The PlayStation®Home Crypto Tool was put together by Rew from the Home Laboratory PlayStation®Home preservation group.

Discord -> https://dsc.gg/homelaboratory
