// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using System.Text;

namespace EncryptorDecrpytor.Console;
public static class Encryptor
{
  public static byte[] Salt { get; set; } = Array.Empty<byte>();

  public static string Encrypt(string text, string key)
  {
    byte[] textBytes = Encoding.UTF8.GetBytes(text);

    Rfc2898DeriveBytes passwordBytes;
    if (Salt.Length == 0)
    {
      // Derive a new password using the PBKDF2 algorithm and a random salt
      passwordBytes = new Rfc2898DeriveBytes(key, 20);

      Salt = passwordBytes.Salt;
    }
    else
    {
      // Derive a new password using the PBKDF2 algorithm and the salt
      passwordBytes = new Rfc2898DeriveBytes(key, Salt);
    }

    using Aes aes = Aes.Create();
    aes.Key = passwordBytes.GetBytes(32);
    aes.IV = passwordBytes.GetBytes(16);

    ICryptoTransform transform = aes.CreateEncryptor();
    byte[] results = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
    return Convert.ToBase64String(results);
  }

  public static string Decipher(string hash, string key)
  {
    byte[] encryptedBytes = Convert.FromBase64String(hash);

    // Derive the password using the PBKDF2 algorithm
    Rfc2898DeriveBytes passwordBytes = new Rfc2898DeriveBytes(key, Salt);

    // Use the password to decrypt the encrypted string
    Aes aes = Aes.Create();
    aes.Key = passwordBytes.GetBytes(32);
    aes.IV = passwordBytes.GetBytes(16);

    ICryptoTransform transform = aes.CreateDecryptor();
    byte[] results = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
    return Encoding.UTF8.GetString(results);
  }
}