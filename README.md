# U-Prove Crypto SDK V1.1.3 (C# Edition)


The __U-Prove Crypto SDK__ V1.1 (C# Edition) implements the U-Prove Cryptographic
Specification V1.1 Revision 3 [UPCS]. This SDK was developed by Microsoft to
support experimentation with the foundational features of the U-Prove technology.
It is made available under the Apache 2.0 open-source license, with patent
rights granted under the Open Specification Promise.

For more information about U-Prove, visit http://www.microsoft.com/u-prove.

<br>

## CONTENTS:

 - LICENSE: The license and patent grant under which this package is distributed
 - docs\: documentation and test vectors
 - ThirdParty\: Bouncy Castle library files
 - UProveCrypto.sln: Visual Studio solution file
 - UProveCrypto\: SDK project
 - UProveParams\: Recommended parameters generation project (not included in
                  solution by default)
 - UProveSample\: Sample project
 - UProveTestVectors\: Test vectors generation project (not included in
                       solution by default)
 - UProveUnitTest\: Unit test project

<br>

## REQUIREMENTS
- .NET SDK 6.0.x or 7.0.x &nbsp;&nbsp;  https://dotnet.microsoft.com/en-us/download/dotnet/6.0
- C#

<br>

## BUILDING THE SDK:

#### Visual Studio 2022
Open the solution file (UProveCrypto.sln) in Visual Studio 2022 and select __Build Solution__ from the __Build__ menu.

#### Visual Studio Code
Open the project folder with VS Code. Select the __Terminal__ menu; select __Run Build Task...__ (Ctrl+Shift+b)_ to perform a build. For a Debug build, select the __Terminal__ menu; select __Run Task...__; select __build Debug__ from the command menu.

#### Command Line
One a command line with __dotnet__ (6.0.x+) available, run `dotnet build`. You can specifiy the build config with the additional `-c Debug` or `-c Release` parameters.

<br>

## GENERATING RECOMMENDED PARAMETERS AND TEST VECTORS

Recommended parameters [UPRP] and test vectors [UPTV] used by the U-Prove SDK 
can be re-generated for validation purposes by loading and running the UProveParams
and UProveTestVectors projects, respectively. The projects depend on the full
BouncyCastle library, and are therefore not included in the UProveCrypto.sln file
by default. BouncyCastle must be obtained from 
http://www.bouncycastle.org/csharp/, the compiled DLL must be placed under
"ThirdParty\BouncyCastle\bc\BouncyCastle.dll", and the two projects must be added
to the solution before compiling it.

<br>

## USING THE UNIT TESTS:

#### Visual Studio 2022

In the __Test__ menu of Visual Studio, select the __Run All Tests__ (Ctrl+R,A). Note that a complete test run takes some
time to complete.

#### Visual Studio Code
Select the __Terminal__ menu; select __Run Task...__; select __test__ from the command menu.

#### Command Line
One a command line with __dotnet__ (6.0.x) available, run `dotnet test -v n`. 

<br>

## USING THE SDK:

Add the UProveCrypto assembly to the set of References for a project.

<br>

## NOTES:

This code was formerly hosted on CodePlex (https://uprovecsharp.codeplex.com).
The following changes have been made to the original code:
 - The solution has been updated to Visual Studio 2022.
 - The Bouncy Castle patch (https://uprovecsharp.codeplex.com/SourceControl/list/patches)
   has been applied, improving efficiency of math operations.

<br>

## REFERENCES:


[UPCS]    Christian Paquin, Greg Zaverucha. U-Prove Cryptographic Specification V1.1.  
          Microsoft Corporation, December 2013. http://www.microsoft.com/u-prove.  
	  "docs/U-Prove Cryptographic Specification V1.1 Revision 3.pdf"

[UPTV]	  U-Prove Cryptographic Test Vectors V1.1 (Revision 3)  
          http://research.microsoft.com/apps/pubs/default.aspx?id=166983
	  docs/testvectors

[UPRP]    U-Prove Recommended Parameters Profile V1.1 (Revision 2)  
          http://research.microsoft.com/apps/pubs/default.aspx?id=166972
	  "docs/U-Prove Recommended Parameters Profile V1.1 Revision 2.pdf"
