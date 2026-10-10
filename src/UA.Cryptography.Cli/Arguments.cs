namespace UA.Cryptography.Cli;

/// <summary>A command-line usage error: reported with the command's help and exit code 2.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>
/// Parsed options of one command: <c>--name value</c>, <c>--name=value</c> and flags. Only the options the command
/// declares are accepted; repeatable options collect every value.
/// </summary>
internal sealed class Arguments
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    public Arguments(IEnumerable<string> args, IReadOnlyCollection<string> options, IReadOnlyCollection<string> flags)
    {
        List<string> list = args.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            string arg = list[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
                throw new UsageException($"Unexpected argument '{arg}'.");
            string name = arg[2..];
            string? value = null;
            int eq = name.IndexOf('=');
            if (eq >= 0)
            {
                value = name[(eq + 1)..];
                name = name[..eq];
            }

            if (flags.Contains(name))
            {
                if (value is not null)
                    throw new UsageException($"--{name} takes no value.");
                _flags.Add(name);
            }
            else if (options.Contains(name))
            {
                if (value is null)
                {
                    if (i + 1 >= list.Count || list[i + 1].StartsWith("--", StringComparison.Ordinal))
                        throw new UsageException($"--{name} needs a value.");
                    value = list[++i];
                }
                if (!_values.TryGetValue(name, out List<string>? values))
                    _values[name] = values = [];
                values.Add(value);
            }
            else
            {
                throw new UsageException($"Unknown option --{name}.");
            }
        }
    }

    public bool Flag(string name) => _flags.Contains(name);

    public string? Optional(string name) => _values.TryGetValue(name, out List<string>? v)
        ? v.Count == 1 ? v[0] : throw new UsageException($"--{name} is given more than once.")
        : null;

    public string Required(string name) => Optional(name) ?? throw new UsageException($"--{name} is required.");

    public IReadOnlyList<string> All(string name) => _values.TryGetValue(name, out List<string>? v) ? v : [];

    public int Int(string name, int defaultValue)
    {
        string? text = Optional(name);
        if (text is null)
            return defaultValue;
        return int.TryParse(text, out int value) && value > 0 ? value : throw new UsageException($"--{name} must be a positive number.");
    }
}
