
using System;
using System.Security.Cryptography;

namespace ChallengeResponse
{
    public class Server
    {
        private static Server instance;
        public static Server Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new Server();
                }
                return instance;
            }
        }

        private RSACryptoServiceProvider rsa;
        public RSAEncryptionPadding OAEPPadding { get; }

        private Server()
        {
            rsa = new RSACryptoServiceProvider();
            OAEPPadding = RSAEncryptionPadding.OaepSHA512;
        }

        public RSAParameters getRSAParameters()
        {
            return rsa.ExportParameters(false);
        }

        public byte[] RSADecrypt(byte[] DataToDecrypt, bool DoOAEPPadding)
        {
            try
            {
                //Decrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later. 
                byte[] decryptedData = rsa.Decrypt(DataToDecrypt, OAEPPadding);
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }
    }
}
