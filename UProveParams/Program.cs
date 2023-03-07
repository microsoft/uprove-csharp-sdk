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

namespace UProveParams
{
    /// <summary>
    /// This program generates the U-Prove recommended parameters for issuers.
    /// </summary>
    public class Program
    {
        static string[] groupNames = { "P-256", "P-384", "P-521" };
        static Formatter.Type[] formatterTypes = { 
            // Formatter.Type.code, // uncomment to generate C++ code-style output
            // Formatter.Type.codeCSharp, // uncomment to generate C# code-style output
            Formatter.Type.doc 
        };

        /// <summary>
        /// Generates the recommended parameters.
        /// </summary>
        /// <param name="args">Output directory.</param>
        static void Main(string[] args)
        {
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
            try
            {
                foreach (Formatter.Type formatterType in formatterTypes)
                {
                    foreach (string groupName in groupNames)
                    {
                        string outputFile = Path.Combine(outputPath, "recommendedparams_" + groupName + "_" + formatterType + ".txt");
                        writer = new System.IO.StreamWriter(outputFile);
                        Formatter formatter = new Formatter(formatterType, writer);
                        formatter.PrintText("U-Prove Recommended Parameters (" + groupName + ")");
                        ECRecommendedParameters.Print(formatter, groupName);
                        Console.WriteLine("recommended parameters " + groupName + " written to " + outputFile);
                        writer.Close();
                        writer = null;
                    }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                Console.Error.WriteLine(e.StackTrace);
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
