using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AesFileEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string original = "Here is some data 2 encrypt!";
            //using (var sourceStream = GenerateStreamFromString(original))
            //using (var destinationStream = File.Create(@"C:\temp\encryptedText.txt"))
            using (var provider = new AesCryptoServiceProvider())
            //using (var cryptoTransform = provider.CreateEncryptor())
            //using (var cryptoStream = new CryptoStream(destinationStream, cryptoTransform, CryptoStreamMode.Write))
            {
                byte[] ivKey = Combine(provider.IV, provider.Key);
                Console.WriteLine("IvyKey Length:   {0}", ivKey.Length);
                //destinationStream.Write(ivKey, 0, ivKey.Length);
                //Console.WriteLine("Destination Length:   {0}", destinationStream.Length);
                //sourceStream.CopyTo(cryptoStream);
                //Console.WriteLine(Convert.ToBase64String(provider.Key));
                //Console.WriteLine(Convert.ToBase64String(provider.IV));
                //Console.WriteLine("Key Length:   {0}", provider.Key.Length);
                //Console.WriteLine("IV Length:   {0}", provider.IV.Length);

                //encrypt destination stream using cert public key
                byte[] encryptedOriginal = EncryptStringToBytes_Aes(original, provider.Key, provider.IV);
                byte[] paddedByteArray = Combine(ivKey, encryptedOriginal);

                //GET CERT
                X509Certificate2 cert = new X509Certificate2();
                byte[] encryptedPackage = EncryptDataOaepSha1(cert, paddedByteArray);

                //WRITE INTO FILE

            }

            FileDecryption();
        }

        static void FileDecryption()
        {
            using (var sourceStream = File.OpenRead(@"C:\temp\encryptedText.txt"))
            //using (var destinationStream = File.Create(@"C:\temp\decryptedText.txt"))
            using (var provider = new AesCryptoServiceProvider())
            {
                Console.WriteLine("Encrypted Length:   {0}", sourceStream.Length);
                var IV = new byte[provider.IV.Length];
                var Key = new byte[provider.Key.Length];
                sourceStream.Read(IV, 0, 16);
                Console.WriteLine(Convert.ToBase64String(IV));
                //after the first sourceStream reads it, it has moved on. so read from 0 again and get the next 32 bytes
                sourceStream.Read(Key, 0, 32);
                Console.WriteLine(Convert.ToBase64String(Key));

                using (var cryptoTransform = provider.CreateDecryptor(Key, IV))
                using (var cryptoStream = new CryptoStream(sourceStream, cryptoTransform, CryptoStreamMode.Read))
                {
                    //cryptoStream.CopyTo(destinationStream);
                    StreamReader reader = new StreamReader(cryptoStream);
                    Console.WriteLine(reader.ReadToEnd());
                }
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        public static byte[] EncryptDataOaepSha1(X509Certificate2 cert, byte[] data)
        {
            // GetRSAPublicKey returns an object with an independent lifetime, so it should be
            // handled via a using statement.
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                // OAEP allows for multiple hashing algorithms, what was formermly just "OAEP" is
                // now OAEP-SHA1.
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            }
        }

        public static byte[] DecryptDataOaepSha1(X509Certificate2 cert, byte[] data)
        {
            // GetRSAPrivateKey returns an object with an independent lifetime, so it should be
            // handled via a using statement.
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
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
