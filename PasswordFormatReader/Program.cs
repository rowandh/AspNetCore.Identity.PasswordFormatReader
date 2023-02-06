using System;
using System.Net.NetworkInformation;

namespace PasswordFormatReader
{
    internal class Program
    {
        // Based on https://www.blinkingcaret.com/2017/11/29/asp-net-identity-passwordhash/
        static void Main(string[] args)
        {
            // Hashed password "hashthis"
            var hashthis = "AQAAAAEAACcQAAAAEFONey6MHOwUhwwylVJr7TcuHW27zmQdjRafj6FfI4EdhNb8AWT+CiwotDHw+sgb9Q==";

            var passwordHash = args.Length > 1 ? args [0] : hashthis;

            byte[] decodedPasswordHash = Convert.FromBase64String(passwordHash);

            int identityVersion = decodedPasswordHash[0];
            byte[] byteArray = new byte[4];

            Array.Copy(decodedPasswordHash, 1, byteArray, 0, 4);
            Array.Reverse(byteArray);
            uint keyDerivationFunction = BitConverter.ToUInt32(byteArray);

            Array.Copy(decodedPasswordHash, 5, byteArray, 0, 4);
            Array.Reverse(byteArray);
            uint iterations = BitConverter.ToUInt32(byteArray);

            Array.Copy(decodedPasswordHash, 9, byteArray, 0, 4);
            Array.Reverse(byteArray);
            uint saltSize = BitConverter.ToUInt32(byteArray);

            byteArray = new byte[16];
            Array.Copy(decodedPasswordHash, 13, byteArray, 0, 16);
            string salt = Convert.ToBase64String(byteArray).Trim(' ');

            byteArray = new byte[32];
            Array.Copy(decodedPasswordHash, 29, byteArray, 0, 32);
            string hash = Convert.ToBase64String(byteArray).Trim(' ');

            Console.WriteLine($"Input hash: {passwordHash}");
            Console.WriteLine($"IdentityVersionByte: {identityVersion} ({GetIdentityVersion(identityVersion)})");
            Console.WriteLine($"Key: {keyDerivationFunction} ({GetKeyDerivationPrf(keyDerivationFunction)})");
            Console.WriteLine($"Iterations: {iterations}");
            Console.WriteLine($"SaltSize: {saltSize}");
            Console.WriteLine($"Salt (base64): {salt}");
            Console.WriteLine($"Hash (base64): {hash}");

            Console.ReadKey();
        }

        public static string GetIdentityVersion(int versionByte)
        {
            return versionByte switch
            {
                0 => "IdentityV2",
                1 => "IdentityV3",
                _ => throw new NotImplementedException()
            };
        }

        public static string GetKeyDerivationPrf(uint keyDerivationPrf)
        {
            return keyDerivationPrf switch
            {
                1 => "HMACSHA256",
                2 => "HMACSHA512",
                _ => "HMACSHA1",
            };
        }
    }
}
