﻿using System.Threading;

namespace ChallengeResponse
{
    public class Client
    {
        public string Login { get; set; }
        public string Password { get; set; }

        public Client(string login, string password)
        {
            Login = login;
            Password = password;
        }

        public string GenerateClientMessage(bool sleepThread = false)
        {
            string nonce = Server.Instance.GenerateNonce(this);
            if (sleepThread)
                Thread.Sleep(500); // Server.TIMEOUT_DELTA + 0.3 = 0.5 = 500ms
            return Tools.Calculate_hash(nonce, Password);
        }
    }
}
