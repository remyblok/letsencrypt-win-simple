using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Win32.TaskScheduler;

namespace letsencrypt_webrole.Services
{
    class RenewalService
    {
        private readonly Options _options;

        public RenewalService(Options options)
        {
            _options = options;
        }

        private static string CleanFileName(string fileName)
        {
            return Path.GetInvalidFileNameChars()
                .Aggregate(fileName, (current, c) => current.Replace(c.ToString(), string.Empty));
        }

        public void ScheduleRenewTask()
        {
            string taskName = $"Lets encrypt renew {CleanFileName(_options.HostName)}";
            Log.Information($"Creating Task {taskName} with Windows Task scheduler at 9am every day.");

            DateTime now = DateTime.UtcNow;
            DateTime runtime = new DateTime(now.Year, now.Month, now.Day, 9, 0, 0, DateTimeKind.Utc);

            string currentExec = Assembly.GetExecutingAssembly().Location;

            // Create an action that will launch the app with the renew parameters whenever the trigger fires
            string actionString = $"\"{string.Join("\" \"", Environment.GetCommandLineArgs().Skip(1))}\" --renew";

            using (TaskService taskService = new TaskService())
            using (DailyTrigger trigger = new DailyTrigger { DaysInterval = 1, StartBoundary = runtime })
            using (ExecAction action = new ExecAction(currentExec, actionString, Path.GetDirectoryName(currentExec)))
            using (TaskFolder rootFolder = taskService.RootFolder)
            using (TaskDefinition task = taskService.NewTask())
            using (TaskRegistrationInfo reginfo = task.RegistrationInfo)
            using (TriggerCollection triggers = task.Triggers)
            using (ActionCollection actions = task.Actions)
            using (TaskPrincipal principal = task.Principal)
            {
                rootFolder.DeleteTask(taskName, false);

                reginfo.Description = $"Check for renewal of ACME certificates for {_options.HostName}.";
                triggers.Add(trigger);
                actions.Add(action);
                principal.RunLevel = TaskRunLevel.Highest; // need admin
                principal.LogonType = TaskLogonType.ServiceAccount;
                principal.UserId = "SYSTEM";

                rootFolder.RegisterTaskDefinition(taskName, task);
            }
        }
    }
}
