using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using gsudo.Helpers;
using Microsoft.Security.Extensions;

namespace gsudo
{
    public static class IntegrityWarnings
    {
        public const string MissingParentProcess = "W_NULL_PARENT_PROCESS: No valid parent process detected.";
        public const string UnrecognizedCurrentAssemblyName = "W_UNRECOGNIZED_CURRENT_ASSEMBLY_NAME: The name of the current assembly is not recognized.";
        public const string UnrecognizedClientAssemblyName = "W_UNRECOGNIZED_CLIENT_ASSEMBLY_NAME: The RPC service should only be started by the UniGetUI Elevator itself.";
        public const string UnrecognizedCallerAssemblyName = "W_UNRECOGNIZED_PARENT_ASSEMBLY_NAME: The name of the parent assembly is not recognized.";
        public const string UnrecognizedCallerAssemblySignature = "W_UNRECOGNIZED_PARENT_ASSEMBLY_SIGNATURE: The signature of the parent assembly is not recognized";
    }

    public static class IntegrityHelpers
    {
        public const string CURRENT_ASSEMBLY_NAME = "UniGetUI Elevator";

        private static readonly string[] RECOGNIZED_CALLER_ASSEMBLY_NAMES =
        [
            "UniGetUI",
            "WingetUI",
            "AdminByRequest",
#if DEBUG
            "vsdbg-ui"
#endif
        ];

        private static readonly string[] RECOGNIZED_CALLER_ASSEMBLY_SUBJECTS =
        [
            "CN=Marti Climent Lopez, O=Marti Climent Lopez, L=Barcelona, S=Barcelona, C=ES",
            "CN=\"Open Source Developer, Martí Climent López\", O=Open Source Developer, L=Barcelona, S=Barcelona, C=ES",
            "CN=Admin By Request ApS, O=Admin By Request ApS, L=Aalborg, C=DK, SERIALNUMBER=31938112, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=DK",
#if DEBUG
            "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
#endif
        ];

        /// <summary>
        /// Verifies the RPC client process when establishing the named pipes
        /// </summary>
        /// <param name="clientProcess"></param>
        /// <returns></returns>
        public static bool VerifyClientProcess(Process clientProcess)
        {
            if (!CheckProcessName(clientProcess))
            {
                Logger.Instance.Log(IntegrityWarnings.UnrecognizedCurrentAssemblyName, LogLevel.Warning);
                return false;
            }

            // Elevated 'gsudoelevate' service should only be started by the UniGetUI Elevator itself
            if (clientProcess.ProcessName != CURRENT_ASSEMBLY_NAME)
            {
                Logger.Instance.Log(IntegrityWarnings.UnrecognizedClientAssemblyName, LogLevel.Warning);
                return false;
            }

            if (!CheckCallerProcessSignature(clientProcess))
            {
                Logger.Instance.Log(IntegrityWarnings.UnrecognizedCallerAssemblySignature, LogLevel.Warning);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Verifies current process and parent processes
        /// </summary>
        /// <returns></returns>
        public static bool VerifyCallerProcess()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();

                // UniGetUI Elevator calls itself to handle elevation.
                // When such scenario occurs integrity checks must be skipped
                if (currentProcess.GetExeName() == currentProcess.GetParentProcess()?.GetExeName())
                {
                    return true;
                }

                // We don't want this file to be renamed, a renamed
                // file can mislead the user
                if (!CheckProcessName(currentProcess))
                {
                    Logger.Instance.Log(IntegrityWarnings.UnrecognizedCurrentAssemblyName, LogLevel.Warning);
                    return false;
                }

                var currentDirectory = Path.GetDirectoryName(currentProcess.MainModule?.FileName);
                var helperDll = Path.Join(currentDirectory, "getfilesiginforedist.dll");
                if (!File.Exists(helperDll))
                {
                    Logger.Instance.Log("W_HELPER_DLL_NOT_FOUND", LogLevel.Warning);
                    return false;
                }

                byte[] fileHash;
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(helperDll))
                    fileHash = sha256.ComputeHash(stream);

                string fileHashString = BitConverter.ToString(fileHash).Replace("-", "").ToLowerInvariant();
                if (fileHashString != "153eefb2eafa8b2b909854cc1f941350efb1170e179a299de8836b8ec5ce6a7a")
                {
                    Logger.Instance.Log("W_HELPER_DLL_HASH_MISMATCH", LogLevel.Warning);
                    return false;
                }

                // We don't want the parent process name to be different from UniGetUI
                // While a file can be easily renamed and this is open-source, this is a
                // basic first step.
                var parentProcess = GetParentProcess();

                if (!CheckCallerProcessName(parentProcess))
                {
                    Logger.Instance.Log(IntegrityWarnings.UnrecognizedCallerAssemblyName, LogLevel.Warning);
                    return false;
                }

                // Since the check above is easily circumventable, let's check if the caller signature is
                // recognized.
                if (!CheckCallerProcessSignature(parentProcess))
                {
                    Logger.Instance.Log(IntegrityWarnings.UnrecognizedCallerAssemblySignature, LogLevel.Warning);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Logger.Instance.Log("E_VALIDATION_CRASHED", LogLevel.Error);
                Logger.Instance.Log(ex.ToString(), LogLevel.Error);
                return false;
            }
        }


        private static bool CheckProcessName(Process process)
        {

            if (process.ProcessName != CURRENT_ASSEMBLY_NAME)
            {
                Logger.Instance.Log($"The process name must be set to {CURRENT_ASSEMBLY_NAME}, otherwise some features will not work", LogLevel.Warning);
                return false;
            }

            return true;
        }


        private static bool CheckCallerProcessName(Process callerProcess)
        {
            if (callerProcess is null)
            {
                Logger.Instance.Log(IntegrityWarnings.MissingParentProcess, LogLevel.Warning);
                return false;
            }

            return RECOGNIZED_CALLER_ASSEMBLY_NAMES.Contains(callerProcess.ProcessName);
        }

        public static bool CheckCallerProcessSignature(Process callerProcess)
        {
            if (callerProcess is null)
            {
                Logger.Instance.Log(IntegrityWarnings.MissingParentProcess, LogLevel.Warning);
                return false;
            }

            using (FileStream fs = File.OpenRead(callerProcess.GetExeName()))
            {
                FileSignatureInfo sigInfo = FileSignatureInfo.GetFromFileStream(fs);
                if (sigInfo.State != SignatureState.SignedAndTrusted)
                {
                    Logger.Instance.Log($"Parent process signature is not SignedAndTrusted: {sigInfo.State}", LogLevel.Error);
                    return false;
                }

                if (!RECOGNIZED_CALLER_ASSEMBLY_SUBJECTS.Contains(sigInfo.SigningCertificate.Subject))
                {
                    Logger.Instance.Log($"Subject {sigInfo.SigningCertificate.Subject} is not recognized", LogLevel.Error);
                    return false;
                }
            }

            return true;
        }

        public static Process GetParentProcess()
        {
            var parentProcess = Process.GetCurrentProcess();

            while (parentProcess?.ProcessName == CURRENT_ASSEMBLY_NAME)
                parentProcess = parentProcess.GetParentProcess();

            return parentProcess;
        }
    }
}