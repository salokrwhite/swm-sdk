using SwmSdk;

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: SwmCrossLanguageHelper <app-id> <storage-directory>");
    return 2;
}

using var client = new SwmClient(new SwmClientOptions
{
    BaseUrl = "https://swm.example.test",
    AppId = args[0],
    ReleaseId = "00000000-0000-0000-0000-000000000501",
    Version = "1.0.0",
    RootTrustKeyId = "crosslang-root",
    RootTrustPublicKey = Convert.ToBase64String(new byte[32]),
    StorageDirectory = args[1],
});

Console.WriteLine("device_id=" + client.DeviceId);
Console.WriteLine("install_id=" + client.InstallId);
Console.WriteLine("key_id=" + client.DeviceKeyId);
Console.WriteLine("key_thumbprint=" + client.KeyThumbprint);
return 0;
