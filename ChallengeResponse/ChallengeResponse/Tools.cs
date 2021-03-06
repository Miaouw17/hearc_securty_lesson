﻿using System.Security.Cryptography;
using System.Text;

namespace ChallengeResponse
{
    public static class Tools
    {
        // Hash SHA512
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512?redirectedfrom=MSDN&view=netframework-4.7.2#code-snippet-1
        private static HashAlgorithm hash = new SHA512CryptoServiceProvider();

        // https://csharp.hotexamples.com/examples/System.Security.Cryptography/SHA512CryptoServiceProvider/-/php-sha512cryptoserviceprovider-class-examples.html
        public static string Calculate_hash(string nonce, string password)
        {
            var encoded_string = EncodeUTF8((nonce + password));

            return Encoding.UTF8.GetString(hash.ComputeHash(encoded_string));
        }

        private static byte[] EncodeUTF8(string msg)
        {
            string propEncodeString = string.Empty;

            byte[] utf8_Bytes = new byte[msg.Length];
            for (int i = 0; i < msg.Length; ++i)
            {
                utf8_Bytes[i] = (byte)msg[i];
            }

            return utf8_Bytes;
        }
    }
}
