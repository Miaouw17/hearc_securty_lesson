using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ChallengeResponse
{
    class Program
    {
        static void Main(string[] args)
        {
            var server = Server.Instance;

            Console.WriteLine("Authentification successful : ");
            var client = new Client("test", "pass1234");
            server.Register(client);
            var nonce = client.AskNonce();

            var login_message = client.GenerateClientMessage(nonce);
            var is_ok = server.Authenticate(client, login_message);
            Console.WriteLine(server.ResponseMESSAGE(is_ok));

            //========================================================//

            Console.WriteLine("\n\nNonce Timeout : ");
            var client2 = new Client("test2", "pass1234");
            server.Register(client2);
            var nonce2 = client2.AskNonce();
            
            Thread.Sleep(300); // Server.TIMEOUT_DELTA + 0.1 = 0.3 = 300ms
            var login_message2 = client2.GenerateClientMessage(nonce2);
            var is_ok2 = server.Authenticate(client2, login_message2);
            Console.WriteLine(server.ResponseMESSAGE(is_ok2));

            //========================================================//

            Console.WriteLine("\n\nReplay Attack : ");
            var client3 = new Client("test3", "pass1234");
            server.Register(client3);
            var nonce3 = client3.AskNonce();

            var login_message3 = client3.GenerateClientMessage(nonce3);
            var is_ok3 = server.Authenticate(client3, login_message3);
            Console.WriteLine(server.ResponseMESSAGE(is_ok3));

            var is_ok_replay = server.Authenticate(client, login_message3);
            Console.WriteLine(server.ResponseMESSAGE(is_ok_replay));

            //========================================================//

            Console.ReadLine();
        }
    }
}
