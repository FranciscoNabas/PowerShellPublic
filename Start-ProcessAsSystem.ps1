
function Start-ProcessAsSystem {
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath,

        [Parameter()]
        [string]$Arguments
    )

#requires -RunAsAdministrator

    # Simple function to delete the relay service.
    function Remove-RelayService {

        param([ref]$ScmHandle)

        $DELETE = 0x00010000
        $hService = [Utilities.Service]::OpenService($ScmHandle.Value, 'SystemProcessRelayService', $DELETE)
        if ($hService -eq [IntPtr]::Zero) {
            throw [System.ComponentModel.Win32Exception]::new([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }

        try {
            if (![Utilities.Service]::DeleteService($hService)) {
                throw [System.ComponentModel.Win32Exception]::new([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
        }
        finally {
            [void][Utilities.Service]::CloseServiceHandle($hService)
        }
    }

    # This code is our service. When it starts it creates a named pipe server and waits for connection.
    # Every time a request is processed a new server starts, accepting multiple requests.
    # This operation is synchronous, there is only one pipe server running at the time.
    $serviceSignature = @'
namespace SystemRelayService
{
    using System;
    using System.IO;
    using System.IO.Pipes;
    using System.Threading;
    using System.Diagnostics;
    using System.ServiceProcess;
    using System.Threading.Tasks;
    using System.Text.RegularExpressions;

    internal static class Program
    {
        static void Main(string[] args)
        {
            ServiceBase[] ServicesToRun = new ServiceBase[] { new RelayService() };
            ServiceBase.Run(ServicesToRun);
        }
    }

    internal class ProcessInformation
    {
        internal string ModuleName { get; set; }
        internal string Arguments { get; set; }
    }

    public class RelayService : ServiceBase
    {
        private static readonly CancellationTokenSource _cancelToken = new CancellationTokenSource();

        protected override void OnStart(string[] args)
        {
            ThreadPool.QueueUserWorkItem(new WaitCallback(IpcServer), _cancelToken.Token);
        }

        protected override void OnStop()
        {
            _cancelToken.Cancel();
            _cancelToken.Dispose();
        }

        private static void IpcServer(object data)
        {
            CancellationToken token = (CancellationToken)data;

            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("SystemRelayServicePipe", PipeDirection.InOut))
            {
                // Calling 'WaitForConnectionAsync' so we can pass our cancellation token.
                Task waitTask = pipeServer.WaitForConnectionAsync(token);
                waitTask.Wait();

                string message;
                using (StreamReader reader = new StreamReader(pipeServer))
                {
                    message = reader.ReadToEnd();
                }

                ProcessInformation processInfo = new ProcessInformation();

                Regex modRx = new Regex(@"(?<=<!\[MODULE\[)(.*)(?=]MODULE]!>)");
                MatchCollection modMatches = modRx.Matches(message);
                if (modMatches.Count > 0)
                    processInfo.ModuleName = modMatches[0].Value;
                
                Regex argsRx = new Regex(@"(?<=<!\[ARGS\[)(.*)(?=]ARGS]!>)");
                MatchCollection argsMatches = argsRx.Matches(message);
                if (argsMatches.Count > 0)
                    processInfo.Arguments = argsMatches[0].Value;

                if (!string.IsNullOrEmpty(processInfo.ModuleName))
                    ProcessFactory(processInfo);
            }

            if (token.IsCancellationRequested)
                return;

            ThreadPool.QueueUserWorkItem(new WaitCallback(IpcServer), _cancelToken.Token);
        }

        private static void ProcessFactory(ProcessInformation processInfo)
        {
            Process process = new Process();
            process.StartInfo.FileName = processInfo.ModuleName;
            process.StartInfo.Arguments = processInfo.Arguments;

            try { process.Start(); }
            catch (Exception) { }
        }
    }
}
'@

    # This utility contains the methods to delete a service.
    # 'Remove-Service' is only available in PowerShell 'Core', or with the 'WindowsUtils' module.
    $utilitiesSignature = @'
namespace Utilities
{
    using System;
    using System.Runtime.InteropServices;

    public class Service
    {
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")]
        public static extern IntPtr OpenSCManager(
            string lpMachineName,
            string lpDatabaseName,
            uint dwDesiredAccess
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")]
        public static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            uint dwDesiredAccess
        );

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
    }
}
'@

    try {
        Add-Type -TypeDefinition $utilitiesSignature -ErrorAction Stop
    }
    catch { }

    # Checking if the service already exists.
    $SC_MANAGER_CONNECT = 0x0001
    $hScm = [Utilities.Service]::OpenSCManager($null, 'ServicesActive', $SC_MANAGER_CONNECT)
    if ($hScm -eq [IntPtr]::Zero) {
        throw [System.ComponentModel.Win32Exception]::new([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }

    if (Get-Service -Name 'SystemProcessRelayService' -ErrorAction SilentlyContinue) {
        Stop-Service -Name 'SystemProcessRelayService' -Force -ErrorAction SilentlyContinue
        Remove-RelayService -ScmHandle ([ref]$hScm)
    }
    Remove-Item -Path "$env:SystemRoot\System32\SystemProcessRelayService.exe" -Force -ErrorAction SilentlyContinue

    # Previously we were using 'Add-Type' with '-OutputAssembly' and '-OutputType', but this caused the
    # service failing to start. So we switched to the 'ICodeCompiler' interface, which is also only
    # available for .NET Framework.
    $svcGenerationSb = {

        param([string]$TypeDefinition)

        $codeProvider = [Microsoft.CSharp.CSharpCodeProvider]::new()
        $compiler = $codeProvider.CreateCompiler()
        
        $compParameters = [System.CodeDom.Compiler.CompilerParameters]::new()
        $compParameters.GenerateExecutable = $true
        $compParameters.OutputAssembly = "$env:SystemRoot\System32\SystemProcessRelayService.exe"
        $compParameters.ReferencedAssemblies.AddRange(@(
            'System.dll'
            'System.Core.dll'
            'System.Data.dll'
            'System.Data.DataSetExtensions.dll'
            'System.Net.Http.dll'
            'System.ServiceProcess.dll'
            'System.Xml.dll'
            'System.Xml.Linq.dll'
            'Microsoft.CSharp.dll'
        ))

        $compiler.CompileAssemblyFromSource($compParameters, $TypeDefinition)
    }

    if ($PSVersionTable['PSEdition'] -eq 'Core') {
        $psProcess = [System.Management.Automation.Runspaces.PowerShellProcessInstance]::new([version]'5.1', $null, $null, $false)
        $runspace = [runspacefactory]::CreateOutOfProcessRunspace([System.Management.Automation.Runspaces.TypeTable]::new([string[]]::new(0)), $psProcess)
        $runspace.Open()

        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        [void]$powershell.AddScript($svcGenerationSb).AddParameter('TypeDefinition', $serviceSignature)

        # There's no advantage in calling it asynchronously.
        [void]$powershell.Invoke()

        $powershell.Dispose()
        $runspace.Dispose()
        $psProcess.Dispose()
    }
    else {
        $powershell = [powershell]::Create()
        [void]$powershell.AddScript($svcGenerationSb).AddParameter('TypeDefinition', $serviceSignature)
        [void]$powershell.Invoke()
        $powershell.Dispose()
    }

    if (!(Test-Path -Path "$env:SystemRoot\System32\SystemProcessRelayService.exe" -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::('Could not find the service executable.')
    }

    # Creating the service.
    [void](New-Service -Name 'SystemProcessRelayService' -BinaryPathName "$env:SystemRoot\System32\SystemProcessRelayService.exe" -StartupType Manual -ErrorAction Stop)

    # 'New-Service' returns a service controller, but when testing with Windows PowerShell the
    # GC kept disposing of it. So we are constructing one.
    # Way faster than calling 'Start-Service', 'Stop-Service'.
    $managedService = [System.ServiceProcess.ServiceController]::new('SystemProcessRelayService')
    $managedService.Start()

    # Creating and sending the request.
    # TODO: Convert to JSON?
    $message = "<![MODULE[$FilePath]MODULE]!><![ARGS[$Arguments]ARGS]!>"
    
    $pipeClient = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'SystemRelayServicePipe', [System.IO.Pipes.PipeDirection]::InOut)
    $pipeClient.Connect()

    $streamWriter = [System.IO.StreamWriter]::new($pipeClient)
    $streamWriter.Write($message)

    $streamWriter.Dispose()
    $pipeClient.Dispose()

    # Cleanup.
    # Stop-Service -Name 'SystemProcessRelayService' -Force
    $managedService.Stop()
    $managedService.Dispose()
    Remove-RelayService -ScmHandle ([ref]$hScm)
    [void][Utilities.Service]::CloseServiceHandle($hScm)
}