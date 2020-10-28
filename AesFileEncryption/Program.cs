using System;
using System.IO;
using System.Security.Cryptography;

namespace AesFileEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string original = "Here is some data 2 encrypt!";
            using (var sourceStream = GenerateStreamFromString(original))
            using (var destinationStream = File.Create(@"C:\temp\encryptedText.txt"))
            using (var provider = new AesCryptoServiceProvider())
            using (var cryptoTransform = provider.CreateEncryptor())
            using (var cryptoStream = new CryptoStream(destinationStream, cryptoTransform, CryptoStreamMode.Write))
            {
                byte[] ivKey = Combine(provider.IV, provider.Key);
                Console.WriteLine("IvyKey Length:   {0}", ivKey.Length);
                destinationStream.Write(ivKey, 0, ivKey.Length);
                Console.WriteLine("Destination Length:   {0}", destinationStream.Length);
                sourceStream.CopyTo(cryptoStream);
                Console.WriteLine(Convert.ToBase64String(provider.Key));
                Console.WriteLine(Convert.ToBase64String(provider.IV));
                Console.WriteLine("Key Length:   {0}", provider.Key.Length);
                Console.WriteLine("IV Length:   {0}", provider.IV.Length);
            }

            FileDecryption();
        }

        static void FileDecryption()
        {
            using (var sourceStream = File.OpenRead(@"C:\temp\encryptedText.txt"))
            using (var destinationStream = File.Create(@"C:\temp\decryptedText.txt"))
            using (var provider = new AesCryptoServiceProvider())
            {
                Console.WriteLine("Encrypted Length:   {0}", sourceStream.Length);
                var IV = new byte[provider.IV.Length];
                var Key = new byte[provider.Key.Length];
                sourceStream.Read(IV, 0, 16);
                Console.WriteLine(Convert.ToBase64String(IV));
                sourceStream.Read(Key, 0, 32);
                Console.WriteLine(Convert.ToBase64String(Key));

                using (var cryptoTransform = provider.CreateDecryptor(Key, IV))
                using (var cryptoStream = new CryptoStream(sourceStream, cryptoTransform, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(destinationStream);
                }
            }
        }

        private static Stream GenerateStreamFromString(string s)
        {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] bytes = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, bytes, 0, first.Length);
            Buffer.BlockCopy(second, 0, bytes, first.Length, second.Length);
            return bytes;
        }

    }
}
