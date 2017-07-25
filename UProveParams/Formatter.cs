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

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.IO;
using System.Text;

namespace UProveParams
{
    public class Formatter
    {
        private string CodeVariablePrefix = "const {0} {1}::{2}[] = {{"; // for C++ native test vectors
        private string CodeCSharpVariablePrefix = "static readonly byte[] {0} = {{"; // for C++ native test vectors
        private string CodeVariableSuffix = "};";
        private string TextVariable = "const {0} {1}::{2}[] = \"{3}\";"; // for C++ native test vectors
        private string CodeLabelPrefix = "// ";
        
        public enum Type {doc, code, codeCSharp}; // text, C++, C#
        public Type type { get; private set; }
        private TextWriter writer;

        /// <summary>
        /// Creates a new Formatter.
        /// </summary>
        /// <param name="type">Type of output: doc or code.</param>
        /// <param name="writer">Where to output. If null, defaults to Console.Out.</param>
        public Formatter(Type type, StreamWriter writer)
        {
            this.type = type;
            if (writer == null)
            {
                this.writer = Console.Out;
            }
            else
            {
                this.writer = writer;
            }
        }

        public void PrintText(string text)
        {
            writer.WriteLine(text);
        }

        public void PrintText(string varLabel, string text)
        {
            writer.WriteLine(varLabel + " = " + text);
        }

        public void PrintText(string varLabel, string varType, string varNamespace, string text)
        {
            if (type == Type.code || type == Type.codeCSharp)
            {
                writer.WriteLine(String.Format(TextVariable, varType, varNamespace, varLabel, text));
            }
            else
            {
                writer.WriteLine(varLabel + " = " + text);
            }
        }

        public void PrintBigInteger(string varLabel, BigInteger i)
        {
            PrintBigInteger(varLabel, null, null, i);
        }

        public void PrintBigInteger(string varLabel, string varType, string varNamespace, BigInteger i)
        {
            PrintBigInteger(varLabel, varType, varNamespace, i, -1);
        }

        public void PrintBigInteger(string varLabel, string varType, string varNamespace, BigInteger i, int counter)
        {
            if (type == Type.code)
            {
                writer.WriteLine(String.Format(CodeVariablePrefix, varType, varNamespace, varLabel, ((counter >= 0) ? " (counter = " + counter + ")" : "")));
                WriteSplitHexString(i.ToString(16));
                writer.WriteLine(CodeVariableSuffix);
            }
            if (type == Type.codeCSharp)
            {
                writer.WriteLine(String.Format(CodeCSharpVariablePrefix, varLabel, ((counter >= 0) ? " (counter = " + counter + ")" : "")));
                WriteSplitHexString(i.ToString(16));
                writer.WriteLine(CodeVariableSuffix);
            }
            else if (type == Type.doc)
            {
                writer.WriteLine(varLabel + " = " + i.ToString(16));
                if (counter >= 0) { writer.WriteLine("counter = " + counter); }

            }
        }

        internal void PrintPointCoordinate(string varLabel, string varType, string varNamespace, ECFieldElement coordinate, string coordinateLabel)
        {
            writer.WriteLine(String.Format(CodeCSharpVariablePrefix, varLabel + coordinateLabel));
            WriteSplitHexString(coordinate.ToBigInteger().ToString(16));
            writer.WriteLine(CodeVariableSuffix);
        }

        public void PrintPoint(string varLabel, string varType, string varNamespace, ECPoint point)
        {
            PrintPoint(varLabel, varType, varNamespace, point, -1);
        }

        public void PrintPoint(string varLabel, string varType, string varNamespace, ECPoint point, int counter)
        {
            if (type == Type.code)
            {
                // prints out point according to SEC spec
                writer.WriteLine(String.Format(CodeVariablePrefix, varType, varNamespace, varLabel));
                writer.WriteLine("0x04,"); // point prefix
                WriteSplitHexString(point.X.ToBigInteger().ToString(16));
                writer.WriteLine(",");
                WriteSplitHexString(point.Y.ToBigInteger().ToString(16));
                writer.WriteLine(CodeVariableSuffix);
            }
            if (type == Type.codeCSharp)
            {
                writer.WriteLine(CodeLabelPrefix + varLabel + ((counter >= 0) ? " (counter = " + counter + ")" : ""));
                PrintPointCoordinate(varLabel, varType, varNamespace, point.X, "_x");
                PrintPointCoordinate(varLabel, varType, varNamespace, point.Y, "_y");
                writer.WriteLine();
            }
            else if (type == Type.doc)
            {
                //writer.WriteLine(label);
                writer.WriteLine(varLabel + ".x = " + point.X.ToBigInteger().ToString(16));
                writer.WriteLine(varLabel + ".y = " + point.Y.ToBigInteger().ToString(16));
                if (counter >= 0) { writer.WriteLine("counter = " + counter); }
            }
        }

        internal void WriteSplitHexString(string hexString)
        {
            int counter = 0;
            if (hexString.Length % 2 == 1)
            {
                // odd lenght, prepend a 0
                hexString = "0" + hexString;
            }
            int hexStringLenght = hexString.Length / 2;
            for (int i = 0; i < hexStringLenght; i++)
            {
                writer.Write("0x" + hexString.Substring(i * 2, 2));
                counter = (counter + 1) % 8;
                if (i == (hexStringLenght - 1))
                {
                    // last hex char
                    writer.WriteLine();
                }
                else
                {
                    if (counter == 0)
                    {
                        // end of line
                        writer.WriteLine(",");
                    }
                    else
                    {
                        writer.Write(", ");
                    }
                }
            }
        }

        public void PrintHex(string varLabel, byte[] bytes)
        {
            PrintHex(varLabel, null, null, bytes);
        }

        public void PrintHex(string varLabel, string varType, string varNamespace, byte[] bytes)
        {
            string hexString = BytesToHexString(bytes);
            if (type == Type.code)
            {
                writer.WriteLine(String.Format(CodeVariablePrefix, varType, varNamespace, varLabel));
                WriteSplitHexString(BytesToHexString(bytes));
                writer.WriteLine(CodeVariableSuffix);
            }
            else if (type == Type.doc)
            {
                PrintText(varLabel, hexString);
            }
        }

        public void PrintSet(string varLabel, int[] set)
        {
            PrintSet(varLabel, null, null, set);
        }

        public void PrintSet(string varLabel, string varType, string varNamespace, int[] set)
        {
            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (int i in set)
            {
                if (!first)
                { 
                    sb.Append(",");
                }
                sb.Append(i);
                first = false;
            }
            if (type == Type.code)
            {
                writer.WriteLine(String.Format(CodeVariablePrefix, varType, varNamespace, varLabel));
                writer.WriteLine(sb.ToString());
                writer.WriteLine(CodeVariableSuffix);
            }
            else if (type == Type.doc)
            {
                PrintText(varLabel, sb.ToString());
            }
        }

        public static byte[] HexStringToBytes(string hexString)
        {
            int length = hexString.Length;
            if ((length % 2) != 0)
            {
                // prepend 0
                hexString = "0" + hexString;
            }

            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < length; i += 2)
            {
                try
                {
                    bytes[i / 2] = Byte.Parse(hexString.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
                }
                catch (Exception)
                {
                    throw new ArgumentException("hexString is invalid");
                }
            }
            return bytes;
        }

        public static string BytesToHexString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }

    }
}
