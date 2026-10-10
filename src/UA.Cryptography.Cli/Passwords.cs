using System.Text;

namespace UA.Cryptography.Cli;

/// <summary>
/// The key store password: <c>--password</c> (visible in the process list, for tests and scripts on a private
/// machine), <c>--password-env NAME</c>, <c>--password-file PATH</c> (first line), or typed at the terminal.
/// </summary>
internal static class Passwords
{
    public static readonly string[] Options = ["password", "password-env", "password-file"];

    public static string Read(Arguments args, bool confirm = false)
    {
        if (args.Optional("password") is { } literal)
            return literal;
        if (args.Optional("password-env") is { } variable)
            return Environment.GetEnvironmentVariable(variable) ?? throw new UsageException($"The environment variable {variable} is not set.");
        if (args.Optional("password-file") is { } path)
            return File.ReadLines(path).FirstOrDefault() ?? throw new UsageException($"The password file {path} is empty.");

        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? throw new UsageException("No password: use --password-env, --password-file or type it.");
        string password = Prompt(Console.Error, "Key store password: ");
        if (confirm && Prompt(Console.Error, "Repeat the password: ") != password)
            throw new UsageException("The passwords do not match.");
        return password;
    }

    private static string Prompt(TextWriter output, string text)
    {
        output.Write(text);
        var password = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                    password.Length--;
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
            }
        }
        output.WriteLine();
        return password.ToString();
    }
}
