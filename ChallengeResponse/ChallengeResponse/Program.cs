using System;

namespace ChallengeResponse
{
    class Program
    {
        static void Main(string[] args)
        {
            // QUESTION - REPONSE
            Console.WriteLine("Quel hachage cryptographique utilisez-vous et pourquoi ?");
            // https://en.wikipedia.org/wiki/Cryptographic_hash_function#Attacks_on_cryptographic_hash_algorithms
            Console.WriteLine("> SHA512 (De la bibliothèque Microsoft qui ne précise pas si SHA-1,2 ou 3) : Récent, efficace (256 pourrait comprendre des collisions)\n");
            Console.WriteLine("Quelles précautions pour le générateur aléatoire ?");
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=netframework-4.7.2
            Console.WriteLine("> S'assurer que le générateur de nombre aléatoire soit VRAIMENT (cryptographiquement=qu'on ne peut pas retrouver avec une suite de nombre généré) aléatoire et il faut gérer que 2 nonce puissent être identique (dans notre implémentation : on génére un nonce à chaque requête, dès que le serveur a gérer le message avec ce nonce valide, il le dévalide, si le générateur retombe sur le même nonce, il le revalide)\n");
            Console.WriteLine("Quelles précautions pour la construction garantissant l'unicité du nonce ?");
            Console.WriteLine("> On a un dictionnaire de nonce par utilisateur, pour chaque utilisateur on ne va gérer que sa liste à lui et puisque c'est un dictionnaire, il ne peut y être qu'une fois. Comme on les \"kill\" à chaque fois, il n'y en aura, potentiellement, à chaque fois qu'un seul de valide.\n");
            Console.WriteLine("Quelles précautions pour la durée de validité du nonce ?");
            Console.WriteLine("> Lui donner une durée pas trop grande (dans notre implémentation : on met \"fin à sa vie\" lorsqu'il a été utilisé en plus d'une courte durée, ainsi on se protège du replay attack. \n\n");


            // CODE LOGIC

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
