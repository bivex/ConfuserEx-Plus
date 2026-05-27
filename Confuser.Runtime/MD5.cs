using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Confuser.Runtime
{
    internal static class MD5
    {
        static void Initialize()
        {
            string loc = typeof(MD5).Assembly.Location;
            
            // Protect against in-memory loading (Assembly.Load(byte[])) bypass
            if (string.IsNullOrEmpty(loc))
            {
                Environment.FailFast("In-memory loading detected.");
                Process.GetCurrentProcess().Kill();
                return;
            }

            try 
            {
                using (var bas = new FileStream(loc, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var file = new BinaryReader(bas))
                {
                    if (bas.Length < 64) Fail();

                    int originalLen = (int)bas.Length - 64;
                    byte[] originalData = file.ReadBytes(originalLen);
                    string computedHash = Hash(originalData);
                    
                    file.BaseStream.Position = originalLen;
                    string embeddedHash = Encoding.ASCII.GetString(file.ReadBytes(64));

                    if (computedHash != embeddedHash)
                    {
                        Fail();
                    }
                }
            }
            catch
            {
                Fail();
            }
        }

        static void Fail()
        {
            Environment.FailFast("File corrupted! This application has been manipulated.");
            Process.GetCurrentProcess().Kill();
        }

        static string Hash(byte[] hash)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] salt = Encoding.ASCII.GetBytes("NeonVM_S@lt_2026_Secure_Hash");
                byte[] combined = new byte[hash.Length + salt.Length];
                Buffer.BlockCopy(hash, 0, combined, 0, hash.Length);
                Buffer.BlockCopy(salt, 0, combined, hash.Length, salt.Length);

                byte[] btr = sha256.ComputeHash(combined);
                StringBuilder sb = new StringBuilder();

                foreach (byte ba in btr)
                {
                    sb.Append(ba.ToString("x2").ToLower());
                }
                return sb.ToString();
            }
        }
    }
}