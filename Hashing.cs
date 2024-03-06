
const int keySize = 64;
const int iterations = 350000;
HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
string HashPasword(out byte[] salt,string password="Test123")
{
    salt = RandomNumberGenerator.GetBytes(keySize);

    var hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(password),
        salt,
        iterations,
        hashAlgorithm,
        keySize);

    return Convert.ToHexString(hash);
}
var hash = HashPasword( out var salt, "clear_password");
bool VerifyPassword(string password, string hash, byte[] salt)
{
    var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);

    return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hash));
}
var result = VerifyPassword("clear_password", hash, salt);
Console.WriteLine($"Password hash: {result}");
Console.WriteLine($"Password hash: {hash}");
Console.WriteLine($"Generated salt: {Convert.ToHexString(salt)}");
