// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

string password = "12345678901234567890123456789012";
var cypherMessage = Encryptor.Encrypt("Texto secreto", password);
var plainTextMessage = Encryptor.Decipher(cypherMessage, password);

Console.WriteLine($"Cypher message: {cypherMessage}");
Console.WriteLine($"Plain text message: {plainTextMessage}");