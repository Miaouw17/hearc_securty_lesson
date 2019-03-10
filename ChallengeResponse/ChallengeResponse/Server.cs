
using System;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace ChallengeResponse
{
    public class Server
    {
        private static Server instance;
        public const double TIMEOUT_DELTA = 0.2; // Nonce available time (in seconds)
        public const int NONCE_SIZE = 64;

        public string ResponseMESSAGE(int code)
        {
            string response = "";
            switch (code)
            {
                case 0:
                    response = "CONNECTION_SUCCESSFUL";
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

        private Dictionary<string, string> users; // key : login, value : plain text password
        private Dictionary<string, Dictionary<string, DateTime>> available_nonce; // key : login, value : dict((nonce, time))


        private Server()
        {
            this.users = new Dictionary<string, string>();
            this.available_nonce = new Dictionary<string, Dictionary<string, DateTime>>();
        }


        public void Register(Client c)
        {
            this.users.Add(c.login, c.password);
        }

        public string GenerateNonce(Client c)
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

        public int Authenticate(Client c, string hash)
        {
            if(!users.ContainsKey(c.login))
            {
                return 3;
            }

            if(!available_nonce.ContainsKey(c.login))
            {
                return 4;
            }

            var possible_nonces = available_nonce[c.login];
            var password = users[c.login];

            foreach(var value in possible_nonces)
            {
                var expected_hash = Tools.Calculate_hash(value.Key, c.password);
                if(expected_hash == hash)
                {
                    // reset the nonce list for this user
                    available_nonce[c.login] = new Dictionary<string, DateTime>();
                    if(DateTime.Now <= value.Value)
                    {
                        return 0;
                    }
                    else
                    {
                        return 2;
                    }
                }
            }
            return 4;
        }
    }
}
