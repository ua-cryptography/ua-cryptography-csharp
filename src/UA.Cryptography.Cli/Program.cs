using UA.Cryptography.Cli;

Console.OutputEncoding = System.Text.Encoding.UTF8;
return UaSign.Run(args, Console.Out, Console.Error);
