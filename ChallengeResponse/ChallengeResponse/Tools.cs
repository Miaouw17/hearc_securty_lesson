using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ChallengeResponse
{
    public static class Tools
    {
        // Hash SHA3
        private static HashAlgorithm hash = new SHA512CryptoServiceProvider();

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
