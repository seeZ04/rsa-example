using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

try
{
    var dataPlain = $"hello_iZOTA_checking_signature {DateTime.Now.Minute}";
    var callNodejsResult = CallNodejs(dataPlain);
    if (!callNodejsResult.Item1)
    {
        Console.WriteLine("data plain: " + dataPlain);
        Console.WriteLine($"Call nodejs error: {callNodejsResult.Item2}");
    }
    else
    {
        Console.WriteLine("data plain send: " + dataPlain);
        var result = Verify(dataPlain, callNodejsResult.Item2, "publicKey.pem");
        Console.WriteLine($"private key: {callNodejsResult.Item3}");
        Console.WriteLine($"data plain nodejs received: {callNodejsResult.Item4}");
        Console.WriteLine($"Signature return from nodejs: {callNodejsResult.Item2}");
        Console.WriteLine($"Verify result : {result}");
    }
    Console.ReadKey();
}
catch (Exception ex)
{
    Console.WriteLine("Exception: " + ex.Message);
}

#region call nodejs

static (bool, string, string, string) CallNodejs(string dataPlain)
{
    try
    {
        var nodeFilePath = @"..\..\..\..\rsa-axample-nodejs\index.js";
        var nodeExecutable = "node";

        var start = new ProcessStartInfo
        {
            FileName = nodeExecutable,
            Arguments = $"\"{nodeFilePath}\" \"{dataPlain}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using Process? process = Process.Start(start);
        var output = process?.StandardOutput.ReadToEnd();
        var error = process?.StandardError.ReadToEnd();
        process?.WaitForExit();

        if (!string.IsNullOrEmpty(error))
        {
            Console.WriteLine("Node.js Error:");
            Console.WriteLine(error);
            return (false, error, string.Empty, string.Empty);
        }
        var result = JsonConvert.DeserializeObject<NodejsResponse>(output?.Trim() ?? string.Empty) ?? new NodejsResponse();
        return (true, result.Sign, result.PrivateKey, result.PlainText);
    }
    catch (Exception e)
    {
        return (false, e.Message, string.Empty, string.Empty);
    }
}

#endregion

#region sign and verify

static bool Verify(string data, string signature, string publicFile)
{
    try
    {
        var rootFolder = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\.."));
        var filePath = Path.Combine(rootFolder, "RSA", "publicKey.pem");

        var publicFileText = File.ReadAllText(filePath);
        var publicKeyBlocks = publicFileText.Split("-", StringSplitOptions.RemoveEmptyEntries);
        var strPublicKey = publicKeyBlocks[1];
        var publicKeyBytes = Convert.FromBase64String(strPublicKey);
        using var rsa = RSA.Create();

        if (publicKeyBlocks[0] == "BEGIN PUBLIC KEY")
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
        else if (publicKeyBlocks[0] == "BEGIN CERTIFICATE") rsa.ImportRSAPublicKey(publicKeyBytes, out _);

        var dataByteArray = Encoding.UTF8.GetBytes(data);
        var signatureByteArray = Convert.FromBase64String(signature);
        return rsa.VerifyData(
            dataByteArray,
            signatureByteArray,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
    }
    catch (Exception e)
    {
        Console.WriteLine($"Verify sig error:{e.Message}");
        return false;
    }
}

static string Sign(string dataToSign, string privateFile)
{
    var rootFolder = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\.."));
    var filePath = Path.Combine(rootFolder, "RSA", "privateKey.pem");

    var privateKey = File.ReadAllText(filePath);
    var privateKeyBlocks = privateKey.Split("-", StringSplitOptions.RemoveEmptyEntries);
    var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1].Replace("\r\n", ""));

    using var rsa = RSA.Create();
    if (privateKeyBlocks[0] == "BEGIN PRIVATE KEY")
        rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
    else if (privateKeyBlocks[0] == "BEGIN RSA PRIVATE KEY") rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

    var sig = rsa.SignData(
        Encoding.UTF8.GetBytes(dataToSign),
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);
    var signature = Convert.ToBase64String(sig);

    return signature;
}
#endregion


public class NodejsResponse
{
    public string Sign { get; set; }
    public string PlainText { get; set; }
    public string PrivateKey { get; set; }

    public NodejsResponse()
    {
        PrivateKey = string.Empty;
        Sign = string.Empty;
        PlainText = string.Empty;
    }
}