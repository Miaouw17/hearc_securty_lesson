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

        public string AskNonce()
        {
            return Server.Instance.GenerateNonce(this);
        }

        public string GenerateClientMessage(string nonce)
        {
            return Tools.Calculate_hash(nonce, Password);
        }
    }
}
