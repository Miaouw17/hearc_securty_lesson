using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ChallengeResponse
{
    class Client
    {
        private RSACryptoServiceProvider rsa;
        public string login;
        public string password;

        public Client(string login, string password)
        {
            this.login = login;
            this.password = password;

            rsa = new RSACryptoServiceProvider();
        }

        public string AskNonce(Server s)
        {
            return Server.Instance.GenerateNonce(this);
        }

        public string GenerateClientMessage(string nonce)
        {
            return Tools.Calculate_hash(nonce, this.password);
        }

        public byte[] RSAEncrypt(byte[] DataToEncrypt, bool DoOAEPPadding)
        {
            try
            {
                //Import the RSA Key information. This only needs
                //toinclude the public key information.
                rsa.ImportParameters(Server.Instance.getRSAParameters());

                //Encrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                byte[]  encryptedData = rsa.Encrypt(DataToEncrypt, Server.Instance.OAEPPadding);

                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }
    }
}
