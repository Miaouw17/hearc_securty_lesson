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
        public readonly static string[] ResponseMESSAGE = { "CONNECTION_SUCCESSFUL", "CONNECTION_FAILED", "NONCE_TIMEDOUT", "INVALID_USER", "INVALID_NONCE" };

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

        private Dictionary<string, string> dictUsers; // key : login, value : plain text password
        private Dictionary<string, Dictionary<string, Tuple<string, DateTime>>> dictAvailableNonce; // key : login, value : dict(key : hash, value : tuple(nonce, time))


        private Server()
        {
            dictUsers = new Dictionary<string, string>();
            dictAvailableNonce = new Dictionary<string, Dictionary<string, Tuple<string, DateTime>>>();
        }


        public void Register(Client c)
        {
            if (!dictUsers.ContainsKey(c.Login))
            {
                dictUsers.Add(c.Login, c.Password);
            }
            else
            {
                Console.WriteLine("User already exists !");
            }
        }

        // https://sqlsteve.wordpress.com/2014/04/23/how-to-create-a-nonce-in-c/
        public string GenerateNonce(Client c)
        {
            if (!dictUsers.ContainsKey(c.Login))
            {             //Allocate a buffer
                var nonce = new byte[NONCE_SIZE];
                //Generate a cryptographically random set of bytes
                using (var Rnd = RandomNumberGenerator.Create())
                {
                    Rnd.GetBytes(nonce);
                }

                if (!dictAvailableNonce.ContainsKey(c.Login))
                {
                    dictAvailableNonce.Add(c.Login, new Dictionary<string, Tuple<string, DateTime>>());
                }
                dictAvailableNonce[c.Login].Add(Tools.Calculate_hash(Convert.ToString(nonce), dictUsers[c.Login]), new Tuple<string, DateTime>(Convert.ToString(nonce), DateTime.Now.AddSeconds(TIMEOUT_DELTA)));

                //Base64 encode and then return
                return Convert.ToString(nonce);
            }

            return null;
        }

        public int Authenticate(Client c, string hash)
        {
            if(!dictUsers.ContainsKey(c.Login))
            {
                return 3;
            }

            if(!dictAvailableNonce.ContainsKey(c.Login))
            {
                return 4;
            }

            var possible_nonces = dictAvailableNonce[c.Login];
            var password = dictUsers[c.Login];

            if (possible_nonces.ContainsKey(hash))
            {
                if (DateTime.Now <= possible_nonces[hash].Item2)
                    return 0;
                else
                    return 2;
            }

            return 4;
        }
    }
}
