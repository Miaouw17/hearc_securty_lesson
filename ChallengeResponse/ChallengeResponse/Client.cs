using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ChallengeResponse
{
    public class Client
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

        public string AskNonce()
        {
            return Server.Instance.GenerateNonce(this);
        }

        public string GenerateClientMessage(string nonce)
        {
            return Tools.Calculate_hash(nonce, this.password);
        }
    }
}
