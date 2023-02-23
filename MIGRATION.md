# Migrate U-Prove C# Project to .Net 7 with Visual Studio Code

<br>

## Clone UProve C# Project
```
git clone https://github.com/microsoft/uprove-csharp-sdk.git
cd uprove-csharp-sdk
```

<br>

## Install .Net 7.0.x SDK
https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-7.0.200-windows-x64-installer

<br>

## Open Project in VS Code
1. Open new terminal
2. try `dotnet` and you should see output like this:
   ```
   >dotnet

   Usage: dotnet [options]
   Usage: dotnet [path-to-application]

    Options:
    -h|--help         Display help.
    --info            Display .NET information.
    --list-sdks       Display the installed SDKs.
    --list-runtimes   Display the installed runtimes.

    path-to-application:
    The path to an application .dll file to execute.
   ```
3. If not, you may need to update your PATH to add `C:\Program Files\dotnet`

<br>


## .Net Upgrade Assistant
https://dotnet.microsoft.com/en-us/platform/upgrade-assistant/tutorial/install-upgrade-assistant  

1. Install upgrade-assistant tool 
   ````
   dotnet tool install -g --add-source "https://api.nuget.org/v3/index.json" --ignore-failed-sources upgrade-assistant
   ````
2. Open terminal to each individual project root:
   ```
   cd UProveCrypto
   ```
3. Analyze the project:
   ```
   upgrade-assistant analyze ./UProveCrypto.csproj
   ```
4. Upgrade project:
   ```
   upgrade-assistant upgrade ./UProveCrypto.csproj
   ```
   Follow the prompts selecting option '1' until complete
5. In the `*.csproj` file, update TargetFramework to .Net 7.0. The update tool does not consistently update this and you might get an older version.
   ```
   <TargetFramework>net7.0</TargetFramework>
   ```
6. You can delete the backup folder, .sarif file, and .clef file
7. At the terminal, run `dotnet build`. It should succeed with warnings.

<br>

## Build
```
cd <project folder>
dotnet build
```

<br>

## Clean
```
dotnet clean
```

<br>

## Fix UProveUnitTest Serialization
The compiler throws an error for the use of `BinaryFormatter` as being insecure.  
1. I replaced `BinaryFormatter` with `BinaryReader`/`BinaryWriter` and updated the serialization code.
2. Delete the existing items in `SerializationReference` folder as they have the obsolete serialization.
3. Find `CREATE_SERIALIZATION_TEST_FILES` in SerializationTests.cs and set it to `true`
4. Run the tests to generate a new set of .dat files.

<br>

## Run the tests
1. `cd UProveUnitTest`
2. `dotnet test`
3. This will build the code first
4. The tests will begin displaying until complete:
   ```
   Starting test execution, please wait...
   A total of 1 test files matched the specified pattern.
   ```

<br>

## Debugging the tests
1. `set VSTEST_HOST_DEBUG=0`
2. `dotnet test`
3. It will show the current process id to attach to and wait
   ```
   Starting test execution, please wait...
   A total of 1 test files matched the specified pattern.
   Host debugging is enabled. Please attach debugger to testhost process to continue.
   Process Id: 26944, Name: testhost
   ```
4. Click the Debugger icon
5. Select `.NET Core Attach`
6. Select the matching process id from the drop-down list
7. The debugger will attach and be paused.
8. Select the Run button to continue.

<br>

## Update Test Framework References

<br>

## Replace Obsolete RNGCryptoServiceProvider
`warning SYSLIB0023: 'RNGCryptoServiceProvider' is obsolete: 'RNGCryptoServiceProvider is obsolete.`
```
In file \uprove-csharp-sdk\UProveCrypto\Math\bc\FieldZqBCImpl.cs

Change:
private static RNGCryptoServiceProvider rngCSP = new RNGCryptoServiceProvider(); 

To:
private static RandomNumberGenerator rngCSP = RandomNumberGenerator.Create();
```
```
In file \uprove-csharp-sdk\UProveSample\SDKSample.cs

Change:
static private System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider();

To:
static private System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create();
```

<br>

## Replace Obsolete Hash Function
```
In File \uprove-csharp-sdk\UProveCrypto\HashFunction.cs

Change:
    hash =HashAlgorithm.Create(hashAlgorithm);

To:
    switch (hashAlgorithm.ToUpper().Replace("-", ""))
    {
        case "SHA1":
            hash = System.Security.Cryptography.SHA1.Create();
            break;

        case "SHA256":
            hash = System.Security.Cryptography.SHA256.Create();
            break;

        case "SHA384":
            hash = System.Security.Cryptography.SHA384.Create();
            break;

        case "SHA512":
            hash = System.Security.Cryptography.SHA512.Create();
            break;

        default:
            throw new ArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
    }

And Remove:
    if (hash == null)
    {
        throw new ArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
    }
```

<br>

## Update PostBuild Event in UProveUnitTest.csproj
_PostBuildEvent_ and _PreBuildEvent_ are being deprecated in favor of _Targets_ and are no longer working.

Replace This:
```
  <PropertyGroup>
    <PostBuildEvent>xcopy /Y /S "$(ProjectDir)SerializationReference" "$(TargetDir)SerializationReference\"
    xcopy /Y /S "$(ProjectDir)TestVectorData" "$(TargetDir)TestVectorData\"
    </PostBuildEvent>
  </PropertyGroup>
```
With This:
```
  <Target Name="PostBuild" AfterTargets="PostBuildEvent">
    <Exec Command="xcopy /Y /S $(ProjectDir)SerializationReference $(TargetDir)SerializationReference\"/>
    <Exec Command="xcopy /Y /S $(ProjectDir)TestVectorData $(TargetDir)TestVectorData\"/>
  </Target>
```

<br>

## Update SatelliteResourceLanguages
The default build output includes a bunch of unnecessary language assets 
```
In File \UProveUnitTest\UProveUnitTest.csproj

Insert into the first <PropertyGroup>
<SatelliteResourceLanguages>en-US</SatelliteResourceLanguages>
```

<br>

## Add Recommended Extensions
Recommend the C# and .NET Test Explorer extensions.
Create extensions.json in the .vscode folder and insert the following:
```
{
    "recommendations": [
        "ms-dotnettools.csharp",
        "formulahendry.dotnet-test-explorer"
    ]
}
```

<br>

## Add Build Tasks
Create _Tasks_ to build, clean, and run tests.
Create tasks.json in the .vscode folder and insert:
```
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build debug",
            "command": "dotnet",
            "type": "process",
            "args": [
                "build",
                "${workspaceFolder}",
                "/property:GenerateFullPaths=true",
                "/consoleloggerparameters:NoSummary"
            ],
            "problemMatcher": "$msCompile"
        },
        {
            "label": "build Release",
            "command": "dotnet",
            "type": "process",
            "args": [
                "build",
                "${workspaceFolder}",
                "-c",
                "Release"
            ],
            "problemMatcher": "$msCompile"
        },
        {
            "label": "clean Debug",
            "command": "dotnet",
            "type": "process",
            "args": [
                "clean",
                "-c",
                "Debug"
            ],
            "problemMatcher": "$msCompile"
        },
        {
            "label": "clean Release",
            "command": "dotnet",
            "type": "process",
            "args": [
                "clean",
                "-c",
                "Release"
            ],
            "problemMatcher": "$msCompile"
        },
        {
            "label": "test",
            "command": "dotnet",
            "type": "process",
            "args": [
                "test",
                "--verbosity",
                "normal"
            ],
            "problemMatcher": "$msCompile"
        }
    ]
}
```

<br>

## Add Launch Task
This will allow us to attach a debugger to the test runner.
Create launch.json in .vscode and insert:
```
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": ".NET Core Attach",
            "type": "coreclr",
            "request": "attach"
        }
    ]
```

<br>

## Update SerializationReference Reverences
The serialization tests create and copy artifacts to the build folders.
These references are incorrect and need to be updated.

`\uprove-csharp-sdk\UProveUnitTest\SerializationTest.cs`
```
Update:
[DeploymentItem(@"SerializationReference\", "SerializationReference")]

To:
[DeploymentItem(@"..\..\..\SerializationReference\", "SerializationReference")]
```
```
Update:
FileStream fs = File.Open(Path.GetRandomFileName() + ".dat", FileMode.Create);

To:
FileStream fs = File.Open("../../../SerializationReference/" + Path.GetRandomFileName() + ".dat", FileMode.Create);
```

`\uprove-csharp-sdk\UProveUnitTest\TestVectorsTest.cs`
```
Update:
[DeploymentItem(@"TestVectorData\", "TestVectorData")]

To:
[DeploymentItem(@"..\..\..\TestVectorData\", "TestVectorData")]
```

<br>

## Update Test References
    `\uprove-csharp-sdk\UProveUnitTest\UProveUnitTest.csproj`
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.3.2" />
    <PackageReference Include="MSTest.TestAdapter" Version="2.2.10" />
    <PackageReference Include="MSTest.TestFramework" Version="2.2.10" />