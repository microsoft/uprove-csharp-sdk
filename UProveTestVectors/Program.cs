//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//    This code is licensed under the Apache License
//    Version 2.0.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

using System;
using System.IO;
using UProveParams;

namespace UProveTestVectors
{
    class Program
    {
        static readonly bool[] booleans = new bool[] { false, true };

        static readonly string SpecVersion = "V1.1 Revision 5";
        static readonly string FileHeader = "// U-Prove Cryptographic test vectors - " + SpecVersion;
        /// <summary>
        /// Generates the test vectors for multiple protocol variations.
        /// </summary>
        /// <param name="args">args[0]: output directory. If <c>null</c>, then the current directory is used.</param>
        static void Main(string[] args)
        {
            // determine output path
            string outputPath;
            if (args != null && args.Length > 1)
            {
                outputPath = args[0];
                if (!Directory.Exists(outputPath))
                {
                    throw new ArgumentException(outputPath + " does not exist");
                }
            }
            else
            {
                outputPath = Directory.GetCurrentDirectory();
            }

            System.IO.StreamWriter writer = null;
            string outputFile;
            Formatter formatter;
            try
            {
                // print hash vectors
                outputFile = Path.Combine(outputPath, "testvectors_hashing.txt");
                writer = new System.IO.StreamWriter(outputFile);
                formatter = new Formatter(Formatter.Type.doc, writer);
                formatter.PrintText(FileHeader);
                TestVectors.GenerateHashTestVectors(formatter);
                Console.WriteLine("hash test vectors written to " + outputFile);
                writer.Close();
                writer = null;

                // print protocol vectors                
                int uidpIndex = 1;
                // iterate for software-only and device-bound tokens
                foreach (bool supportDevice in booleans)
                {
                    // iterate for lite and full protocol versions
                    foreach (bool lite in booleans) 
                    {
                        // iterate for various disclosed attributes subsets
                        foreach (int[] D in new int[][] {
                                                    new int[] {},
                                                    new int[] { 2, 5 },
                                                    new int[] { 1, 2, 3, 4, 5} })
                        {
                            // print vectors as a text file
                            Formatter.Type formatterType = Formatter.Type.doc;
                            outputFile = Path.Combine(outputPath, "testvectors_EC" + (supportDevice ? "_Device" : "") + ("_D" + D.Length) + (lite ? "_lite" : "") + "_" + formatterType + ".txt");
                            Console.WriteLine("Generating " + outputFile);
                            try
                            {
                                writer = new System.IO.StreamWriter(outputFile);
                                formatter = new Formatter(formatterType, writer);
                                formatter.PrintText(FileHeader);
                                formatter.PrintText("// The following prefixes identify values for U-Prove extensions:");
                                formatter.PrintText("// * 'ie_': identity escrow extension - draft revision 1");
                                formatter.PrintText("// * 'r_': designated-verifier accumulator revocation extension - draft revision 2");
                                formatter.PrintText("// * 'sm_': set membership extension - draft revision 1");
                                string uidp = SpecVersion + "Test Vectors #" + uidpIndex++;
                                TestVectors.GenerateTestVectors(uidp, formatter, supportDevice, lite, 5, D);
                            }
                            catch (Exception e)
                            {
                                var color = Console.ForegroundColor;
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(e.Message);
                                Console.WriteLine(e.StackTrace);
                                Console.ForegroundColor = color;
                            }
                            finally
                            {
                                if (writer != null)
                                {
                                    writer.Close();
                                }
                                writer = null;
                            }
                        }
                    }
                }
            }
            finally
            {
                if (writer != null)
                {
                    writer.Close();
                }
            }
            Console.WriteLine("completed");
            Console.ReadLine();
        }
    }
}
