using System;
using System.Diagnostics;

namespace letsencrypt_webrole.Services
{
    static class Log
    {
        private static TextWriterTraceListener _preInitialzeListener;

        public static void PreInitialize()
        {
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

            _preInitialzeListener = new TextWriterTraceListener(Environment.ExpandEnvironmentVariables("%temp%\\letsencrypt-webrole.log"));
            _preInitialzeListener.WriteLine(new string('=', 40));
            _preInitialzeListener.WriteLine($"Runtime: {DateTime.UtcNow:s}");

            Trace.Listeners.Add(_preInitialzeListener);
            Trace.AutoFlush = true;
        }

        public static void Initialize(Options options)
        {
            Trace.Listeners.Add(new TextWriterTraceListener(options.WellKnownFilePaths[WellKnownFile.LogLocation]));
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            WriteMessage("Execption occured, stopping processing", "FATAL", ConsoleColor.White, ConsoleColor.Red);
            WriteMessage(e.ExceptionObject.ToString(), "FATAL", ConsoleColor.White, ConsoleColor.Red);
            Environment.Exit(-1);
        }

        public static void Information(string message)
        {
            WriteMessage(message, " INFO");
        }

        public static void Error(string message)
        {
            WriteMessage(message, "ERROR", ConsoleColor.Red);
        }

        [Conditional("DEBUG")]
        public static void Debug(string message)
        {
            WriteMessage(message, "DEBUG", ConsoleColor.Green);
        }

        public static void Warning(string message)
        {
            WriteMessage(message, " WARN", ConsoleColor.Yellow);
        }

        private static void WriteMessage(string message, string severity, ConsoleColor? foregroundColor = null, ConsoleColor? backConsoleColor = null)
        {
            Console.ForegroundColor = foregroundColor.GetValueOrDefault(Console.ForegroundColor);
            Console.BackgroundColor = backConsoleColor.GetValueOrDefault(Console.BackgroundColor);

            Console.WriteLine($"{severity}: {message}");

            Console.ResetColor();

            Trace.WriteLine($"{severity}: {message}");
        }


    }
}
