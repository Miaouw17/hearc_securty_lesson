﻿
using System;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace ChallengeResponse
{
    public class Server
    {
        private static Server instance;
        private const double TIMEOUT_DELTA = 0.2; // Nonce available time (in seconds)
        private const int NONCE_SIZE = 64;

        public string ResponseMESSAGE(int code)
        {
            string response = "";
            switch (code)
            {
                case 0:
                    response = "CONNECTION_SUCESSFUL";
                    break;
                case 1:
                    response = "CONNECTION_FAILED";
                    break;
                case 2:
                    response = "NONCE_TIMEDOUT";
                    break;
                case 3:
                    response = "INVALID_USER";
                    break;
                case 4:
                    response = "INVALID_NONCE";
                    break;
            }
            return response;
        }

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

        // RSA
        private RSACryptoServiceProvider rsa;
        public RSAEncryptionPadding OAEPPadding { get; }

       
   
        private Dictionary<string, string> users; // key : login, value : plain text password
        private Dictionary<string, Dictionary<string, DateTime>> available_nonce; // key : login, value : dict((nonce, time))


        private Server()
        {
            this.users = new Dictionary<string, string>();
            this.available_nonce = new Dictionary<string, Dictionary<string, DateTime>>();

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

        private void Register(Client c)
        {
            this.users.Add(c.login, c.password);
        }

        private string GenerateNonce(Client c)
        {
            //Allocate a buffer
            var nonce = new byte[NONCE_SIZE];
            //Generate a cryptographically random set of bytes
            using (var Rnd = RandomNumberGenerator.Create())
            {
                Rnd.GetBytes(nonce);
            }

            if(!available_nonce.ContainsKey(c.login))
            {
                available_nonce.Add(c.login, new Dictionary<string, DateTime>());
            }
            available_nonce[c.login].Add(Convert.ToString(nonce), DateTime.Now.AddSeconds(TIMEOUT_DELTA));

            //Base64 encode and then return
            return Convert.ToString(nonce);
        }

        private int Authenticate(Client c, string hash)
        {
            if(!users.ContainsKey(c.login))
            {
                return 0;
            }

            if(!available_nonce.ContainsKey(c.login))
            {
                return 4;
            }

            var possible_nonces = available_nonce[c.login];
            var password = users[c.login];

            foreach(...) // a trouver
            {
                var expected_hash = Tools.Calculate_Hash(); // TODO
            }

            return 4;
        }
    }
}
