using System;

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

            var login_message = client.GenerateClientMessage();
            var is_ok = server.Authenticate(client, login_message);
            Console.WriteLine(Server.ResponseMESSAGE[is_ok]);

            //========================================================//

            Console.WriteLine("\n\nNonce Timeout : ");
            var client2 = new Client("test2", "pass1234");
            server.Register(client2);
            
            var login_message2 = client2.GenerateClientMessage(true);
            var is_ok2 = server.Authenticate(client2, login_message2);
            Console.WriteLine(Server.ResponseMESSAGE[is_ok2]);

            //========================================================//

            Console.WriteLine("\n\nReplay Attack : ");
            var client3 = new Client("test3", "pass1234");
            server.Register(client3);

            var login_message3 = client3.GenerateClientMessage();
            var is_ok3 = server.Authenticate(client3, login_message3);
            Console.WriteLine(Server.ResponseMESSAGE[is_ok3]);

            // Thread.Sleep(200); PoC replay attack don't work because of alive time of nonce but not protect if it's faster
            var is_ok_replay = server.Authenticate(client3, login_message3);
            Console.WriteLine(Server.ResponseMESSAGE[is_ok_replay]);

            //========================================================//

            Console.WriteLine("\n\nWrong Password : ");
            var client4 = new Client("test4", "pass1234");
            server.Register(client4);

            client4.Password = "Pass1234";
            var login_message4 = client3.GenerateClientMessage();
            var is_ok4 = server.Authenticate(client4, login_message4);
            Console.WriteLine(Server.ResponseMESSAGE[is_ok4]);

            //========================================================//

            Console.WriteLine("\n\nWrong login : ");
            var client5 = new Client("test5", "pass1234");
            server.Register(client5);

            client5.Login = "Test5";
            var login_message5 = client4.GenerateClientMessage();
            var is_ok5 = server.Authenticate(client5, login_message5);
            Console.WriteLine(Server.ResponseMESSAGE[is_ok5]);

            //========================================================//

            Console.WriteLine("\n\nDouble registration : ");
            var client6 = new Client("test6", "pass1234");
            var client7 = new Client("test6", "pass1234");
            server.Register(client6);
            server.Register(client7);

            Console.ReadLine();
        }
    }
}
