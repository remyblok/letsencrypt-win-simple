using System;
using System.Runtime.InteropServices;

namespace letsencrypt_webrole.Services
{
    class NetworkDriveService
    {
        public static void MapWorkingFolder(Options options)
        {
            if (!options.ConnectWorkingFolderAsNetworkDrive)
                return;

            NativeMethods.NETRESOURCE resource = new NativeMethods.NETRESOURCE()
            {
                dwType = NativeMethods.RESOURCETYPE_DISK,
                lpRemoteName = options.WorkingFolder,
            };

            uint error = NativeMethods.WNetAddConnection2(ref resource, options.NetworkDrivePassword, options.NetworkDriveUserName, NativeMethods.CONNECT_TEMPORARY);

            if (error != 0)
                throw new InvalidOperationException($"Failed to connect network drive. Error code {error}");
        }

        private class NativeMethods
        {
            public const uint RESOURCETYPE_DISK = 1;

            public const uint CONNECT_UPDATE_PROFILE = 0x1;
            public const uint CONNECT_UPDATE_RECENT = 0x2;
            public const uint CONNECT_TEMPORARY = 0x4;
            public const uint CONNECT_INTERACTIVE = 0x8;
            public const uint CONNECT_PROMPT = 0x10;
            public const uint CONNECT_REDIRECT = 0x80;
            public const uint CONNECT_CURRENT_MEDIA = 0x200;
            public const uint CONNECT_COMMANDLINE = 0x800;
            public const uint CONNECT_CMD_SAVECRED = 0x1000;
            public const uint CONNECT_CRED_RESET = 0x2000;


            [DllImport("mpr.dll")]
            public static extern uint WNetAddConnection2(
                ref NETRESOURCE lpNetResource, string lpPassword, string lpUsername, uint dwFlags);

            [StructLayout(LayoutKind.Sequential)]
            public struct NETRESOURCE
            {
                public uint dwScope;
                public uint dwType;
                public uint dwDisplayType;
                public uint dwUsage;
                public string lpLocalName;
                public string lpRemoteName;
                public string lpComment;
                public string lpProvider;
            }
        }
    }
}
