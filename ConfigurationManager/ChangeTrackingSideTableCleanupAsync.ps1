<#
    .SYNOPSIS

        This script cleans up back logged change tracking from a SQL database.

    .DESCRIPTION

        This script cleans up back logged change tracking data from side tables asynchronously by creating concurrent PowerShell
        instances, and executing 'sys.sp_flush_CT_internal_table_on_demand'.

        For some reason, this procedure sometimes does not clean all data. To compensate for that, after all tasks finishes we
        run another check, and if there are tables with rows passed retention we clean up one byu one synchronously.

        After the second cleanup, the 'sys.syscommittab' table is cleaned in batches according to the parameter 'RowsToDeletePerIteration'.

    .PARAMETER Database

        The database name.

    .PARAMETER MaxRetryCount

        If one of the tasks fails, this parameter sets how many times to retry the operation. Default is 10.

    .PARAMETER MaxConcurrentTask

        This parameter sets how many tasks are allowed to run simultaneously.
        If this value is zero, the max number of tasks is the number of tables who's side table contains rows passed retention.

    .PARAMETER RowsToDeletePerIteration

        This parameter dictates how many rows are deleted per iteration, and only have effect when cleaning the 'syscommittab'
        or during an atomic cleanup, in the second check.

    .EXAMPLE

        ChangeTrackingSideTableCleanupAsync.ps1 -Database CM_PS1 -Verbose

    .NOTES

        Scripted by: Francisco Nabas.
        Version: 2.1.0
	    Version date: 29-NOV-2023
        Contact: francisconabas@outlook.com

    .LINK

        https://learn.microsoft.com/en-us/archive/blogs/sql_server_team/change-tracking-cleanup-part-1
        https://techcommunity.microsoft.com/t5/sql-server-blog/change-tracking-cleanup-8211-part-2/ba-p/385090
        https://techcommunity.microsoft.com/t5/azure-sql-blog/change-tracking-cleanup-part-3/ba-p/2776578
        https://github.com/FranciscoNabas
    
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$Database,

    [Parameter()]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxRetryCount = 10,

    [Parameter()]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxConcurrentTask = 0,

    [Parameter()]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$RowsToDeletePerIteration = 10000
)

#region Functions
# This function creates logs compatible with the CMTrace.
function Add-Log {

    [CmdletBinding()]
    param (

        [Parameter(
            Position = 0,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Log file full name.'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path = "$PSScriptRoot\Log-$($MyInvocation.MyCommand.Name)-$(Get-Date -Format 'yyyyMMdd-hhmmss').log",

        [Parameter(
            Mandatory,
            Position = 1,
            HelpMessage = 'The log level. Informational, Warning or Error.')]
        [LogLevel]$Level,
        
        [Parameter(
            Mandatory,
            Position = 2,
            HelpMessage = 'The log message.')]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(
            Position = 3,
            HelpMessage = 'The component logging the information.')]
        [string]$Component = $MyInvocation.InvocationName

    )
    
    enum LogLevel {
        Informational = 1
        Warning = 2
        Error = 3
    }
    
    $logText = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}:{8}">'
    $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $thread = [Threading.Thread]::CurrentThread.ManagedThreadId
    $time = [datetime]::Now.ToString('HH:mm:ss.ffff', [System.Globalization.CultureInfo]::InvariantCulture)
    $date = [datetime]::Now.ToString('MM-dd-yyyy', [System.Globalization.CultureInfo]::InvariantCulture)

    $content = [string]::Format($logText, $Message, $time, $date, $Component, $context, $Level.value__, $thread, $MyInvocation.ScriptName, $MyInvocation.ScriptLineNumber)

    try {
        Add-Content -Path $Path -Value $content -Force -ErrorAction Stop
    }
    catch {
        Start-Sleep -Milliseconds 700
        Add-Content -Path $Path -Value $content -Force
    }

}

# This function returns information about tables who's side tables contains rows passed the retention period.
function Get-CTTablesWithRowsPassedRetention([string]$Database) {

    # This scary query just gets the tables who's side tables contains rows beyond
    # the change tracking retention period. Was extracted from 'spDiagChangeTracking'.
    $query = @'
    DECLARE @ProcedureName NVARCHAR(24) = N'spDiagChangeTracking';  
    DECLARE @SiteCode NVARCHAR(3);  
    DECLARE @SiteStatus INT;  
    DECLARE @SQLInstance NVARCHAR(512);  
    DECLARE @SiteServer NVARCHAR(512);  
    DECLARE @DBName SYSNAME;  
    DECLARE @SiteType INT;  
    DECLARE @LogText NVARCHAR(MAX);   
    DECLARE @MessageText NVARCHAR(MAX);  
    DECLARE @SQL NVARCHAR(MAX);  
    DECLARE @StartTime DATETIME;  
    DECLARE @EndTime DATETIME;  
    DECLARE @RetentionUnit INT = 0;  
    DECLARE @RetentionPeriod INT = 0;  
    DECLARE @AutoCleanupVersion BIGINT = 0; -- maintained by SQL autocleanup  
    DECLARE @CleanupVersion BIGINT = 0; -- version we will use for cleanup 
    DECLARE @CleanupTrxID BIGINT = 0;  
    DECLARE @AutoCleanupTrxID BIGINT = 0;  
    DECLARE @AutoCleanupTime DATETIME; -- time for the autocleanup version 
    DECLARE @CleanupTime DATETIME; -- time for the cleanup version 
    DECLARE @CTCutOffTime DATETIME;  
    DECLARE @CTMinTS BIGINT = 0;  
    DECLARE @CTMaxTS BIGINT = 0;  
    DECLARE @CTMinTime DATETIME;  
    DECLARE @Index INT = 0;  
    DECLARE @CTSideTableCount INT = 0;  
    DECLARE @ErrorCount INT = 0;  
    DECLARE @ErrorNumber INT = 0;  
    DECLARE @RetryCount INT = 5;  
    DECLARE @SysCommittabRowCount BIGINT = 0;  
    DECLARE @RowsDeleted BIGINT = 0  
    DECLARE @TableName SYSNAME;  
    DECLARE @RowCount BIGINT = 0;  
    DECLARE @MinXdesID BIGINT = 0;  
    DECLARE @ObjectID BIGINT = 0;  
    DECLARE @Param NVARCHAR(256);  
    DECLARE @RowsBeyondRetention BIGINT = 0;  
    DECLARE @TotalRowsBeyondRetention BIGINT = 0;  
    DECLARE @SideTableMinTime DATETIME;  
    DECLARE @CTMinXdesID BIGINT = 0;  
    DECLARE @SideTableDaysOld INT = 0;  
    DECLARE @ElapsedTimeMins INT = 0;  
    DECLARE @CheckSideTableMinTime BIT = 0
    
    DECLARE @TEMP_TS BIGINT; 
    DECLARE @TS_TIME DATETIME; 
    DECLARE @CalculateCleanupVersion BIT = 0;  

    SET NOCOUNT ON

    --************************************************************************  
    -- General site information  
    --************************************************************************  
    SELECT @SiteCode=SiteCode, @SiteStatus=SiteStatus, @SiteServer=Name, @SQLInstance=SQLInstance, @DBName=ConfigMgrDatabase  
        FROM ServerData WHERE SiteCode = dbo.fnGetSiteCode();  
    
    --************************************************************************  
    -- General changetracking information  
    --************************************************************************  
    
    SET @SysCommittabRowCount = dbo.fnFastRowCount('sys.syscommittab');  
    
    -- Get the cleanup version that is maintained by sql autocleanup job  
    SET @AutoCleanupVersion = (SELECT ISNULL(MIN(cleanup_version),0) FROM sys.change_tracking_tables);  
    
    -- Get the transactionid for the auto cleanup version   
    SET @AutoCleanupTrxID = (SELECT xdes_id FROM sys.syscommittab WHERE commit_ts = @AutoCleanupVersion);  
    
    -- Get the commit time for the auto cleanup version, ideally this is close to the datetime for cutoff   
    SET @AutoCleanupTime = (SELECT commit_time FROM sys.syscommittab WHERE xdes_id = @AutoCleanupTrxID);   
    
    -- Get the retentions settings, for SCCM this should always be 5 days   
    SELECT @RetentionPeriod=retention_period,    
    		   @RetentionUnit=retention_period_units    
    	FROM sys.change_tracking_databases    
    	WHERE database_id = DB_ID();   
    
    -- Get the cleanup time and version based on retention settings (autocleanup values should be close to this if autocleanup is keeping up)   
    IF @RetentionUnit = 1   
    	SET @CTCutOffTime = DATEADD(MINUTE,-@RetentionPeriod,GETUTCDATE())   
    ELSE IF @RetentionUnit = 2   
    	SET @CTCutOffTime = DATEADD(HOUR,-@RetentionPeriod,GETUTCDATE())   
    ELSE IF @RetentionUnit = 3   
    	SET @CTCutOffTime = DATEADD(DAY,-@RetentionPeriod,GETUTCDATE())   
    
    -- get the oldest entry in syscommittab   
    SET @CTMinTS = (SELECT MIN(commit_ts) FROM sys.syscommittab);  
    SELECT @CTMinTime = commit_time, @CTMinXdesID = xdes_id FROM sys.syscommittab WHERE commit_ts = @CTMinTS;  
    
    -- get the latest entry in syscommittab 
    SET @CTMaxTS = (SELECT MAX(commit_ts) FROM sys.syscommittab); 
    
    -- If Autocleanup is beyond the retention period + 2 days then calculate our cleanup version manually 
    -- This can happen if autocleanup isn't working correctly 
    IF (DATEDIFF(Day, @AutoCleanupTime, @CTCutOffTime) > 2) 
    BEGIN 
    	SET @CalculateCleanupVersion = 1 
    END 
    
    -- If we suspect cleanup version is off then calculate this ourselves, we should usually not need to do this 
    IF (@CalculateCleanupVersion = 1) 
    BEGIN 
        -- Looking for closet sequence id to the cutoff time, binary search because commit_time has no index 
        WHILE (@CTMinTS < @CTMaxTS) 
        BEGIN 
            SET @TEMP_TS = (SELECT (@CTMaxTS + @CTMinTS)/2); 
            SET @TEMP_TS = (SELECT MAX(commit_ts) FROM sys.syscommittab WHERE commit_ts <= @TEMP_TS); 
    
            IF (@TEMP_TS = @CTMinTS) -- could not find value 
    			BREAK; 
    
            SET @TS_TIME = (SELECT commit_time FROM sys.syscommittab WHERE commit_ts = @TEMP_TS); 
    
            IF (@TS_TIME = @CTCutOffTime) 
    			SELECT @CTMinTS = @TEMP_TS, @CTMaxTS = @TEMP_TS; --we are done here 
            ELSE IF (@TS_TIME > @CTCutOffTime) 
    			SELECT @CTMaxTS = @TEMP_TS; -- move max value down 
            ELSE IF (@TS_TIME < @CTCutOffTime) 
    			SELECT @CTMinTS = @TEMP_TS; -- move min value up 
         END; 
    
    	 SET @CleanupVersion = CASE WHEN @TS_TIME > @CTCutOffTime THEN @CTMinTS ELSE @CTMaxTS END; 
    
    	 -- Get the transactionid for the cleanup version   
    	SET @CleanupTrxID = (SELECT xdes_id FROM sys.syscommittab WHERE commit_ts = @CleanupVersion);   
    	SET @CleanupTime = (SELECT commit_time FROM sys.syscommittab WHERE xdes_id = @CleanupTrxID);  
    END 
    ELSE 
    BEGIN 
    	SET @CleanupVersion = @AutoCleanupVersion;  
        SET @CleanupTrxID  = @AutoCleanupTrxID; 
        SET @CleanupTime = @AutoCleanupTime; 
    END 
    
    --*************************************************************************************************************************  
    -- Run analysis on changetracking side tables  
    --*************************************************************************************************************************  
    -- Create temporary table to hold data  
    IF OBJECT_ID('tempdb..##CustomChangeTrackingData_') IS NOT NULL  
    BEGIN  
    	DROP TABLE ##CustomChangeTrackingData_  
    END  
    
    CREATE TABLE ##CustomChangeTrackingData_  
    (  
    	ID INT IDENTITY,  
    	TableName SYSNAME,  
    	CTTableName SYSNAME,  
    	ObjectID BIGINT,  
    	CTRowCount BIGINT,  
    	MinXdesID BIGINT,  
    	MinTime DATETIME,  
    	DaysOld INT,  
    	RowsBeyondRetention BIGINT,  
    	AllRowsBeyondRetention BIGINT,  
    	NumRowsOrphaned BIGINT,  
    	NumRowsDeleted BIGINT,  
    	ErrorCount INT,  
    	ErrorNumber INT,
        CleanupTrxID BIGINT,
        CleanupVersion BIGINT
    );  
    
    INSERT INTO ##CustomChangeTrackingData_ (TableName, CTTableName, ObjectID)  
    SELECT OBJECT_NAME(parent_object_id), name, [object_id]  
      FROM sys.internal_tables  
    WHERE internal_type = 209  
    
    SET @CTSideTableCount = (SELECT COUNT(*) FROM ##CustomChangeTrackingData_);  
    
    -- Loop through and get info for each side table  
    WHILE (@Index <= @CTSideTableCount)  
    BEGIN  
    	-- which table are we checking  
    	SELECT TOP(1) @TableName = CTTableName, @ObjectID = ObjectID FROM ##CustomChangeTrackingData_ WHERE ID = @Index;  
    
    	-- get the rowcount  
    	SET @RowCount = (SELECT SUM (CASE WHEN sd.index_id < 2 THEN sd.row_count ELSE 0 END)      
    							FROM sys.dm_db_partition_stats sd   
    						WHERE sd.object_id = @ObjectID);  
    
    	-- get the min version for the table  
    	SET @SQL = N'SELECT @MinXdesIDOUT = MIN(sys_change_xdes_id) FROM sys.' + QUOTENAME(@TableName) + N'  WITH (NOLOCK) ';  
    	SET @Param = N'@MinXdesIDOUT BIGINT OUTPUT'  
    
    	EXEC sp_executesql @SQL, @Param, @MinXdesIDOUT=@MinXdesID OUTPUT  
    
    	-- get the num of rows less than the cleanup trx id  
    	SET @SQL = N'SELECT @countOUT = COUNT(*) FROM sys.' + QUOTENAME(@TableName) + N' WITH (NOLOCK) WHERE sys_change_xdes_id IN   
    	           (SELECT xdes_id FROM sys.syscommittab ssct WHERE ssct.commit_ts <= ' + Cast(@CleanupVersion AS NVARCHAR) + ')';  
    
    	SET @Param = N'@countOUT BIGINT OUTPUT'  
    
    	EXEC sp_executesql @SQL, @Param, @countOUT=@RowsBeyondRetention OUTPUT  
    
    	-- get the total num of rows less than the cleanup trx id, this will include any orphaned records  
    	SET @SQL = N'SELECT @countOUT = COUNT(*) FROM sys.' + QUOTENAME(@TableName) + N' WITH (NOLOCK) WHERE sys_change_xdes_id < ' + CONVERT(NVARCHAR(MAX), @CleanupTrxID) ;  
    	SET @Param = N'@countOUT BIGINT OUTPUT'  
    
    	EXEC sp_executesql @SQL, @Param, @countOUT=@TotalRowsBeyondRetention OUTPUT  
    
    	-- this check can take a while since it requires a full scan syscommittab  
    	IF ((@MinXdesID IS NOT NULL) AND (@CheckSideTableMinTime = 1))  
    	BEGIN  
    		SET @SideTableMinTime = (SELECT commit_time FROM sys.syscommittab WHERE xdes_id = @MinXdesID)  
    		SET @SideTableDaysOld = (SELECT DATEDIFF(Day, @SideTableMinTime, GETUTCDATE()));  
    	END  
    
    	UPDATE ##CustomChangeTrackingData_   
    		SET CTRowCount = @RowCount,  
    		MinXdesID = @MinXdesID,  
    		MinTime = @SideTableMinTime,  
    		DaysOld = @SideTableDaysOld,  
    		RowsBeyondRetention = @RowsBeyondRetention,  
    		AllRowsBeyondRetention = @TotalRowsBeyondRetention,  
    		NumRowsOrphaned = @TotalRowsBeyondRetention - @RowsBeyondRetention,
            CleanupTrxID = @CleanupTrxID,
            CleanupVersion = @CleanupVersion
    	WHERE CTTableName = @TableName;  
    
    	-- reset values  
    	SET @SideTableMinTime = NULL;  
    	SET @SideTableDaysOld = NULL;  
    	SET @MinXdesID = NULL;  
    
    	SET @Index += 1;  
    END

    SELECT * FROM ##CustomChangeTrackingData_ ORDER BY RowsBeyondRetention DESC
    DROP TABLE ##CustomChangeTrackingData_
'@

    try {
        # The above query needs to be run in a DAC connection. This makes it slow, and prevents us from having more than one connection simultaneously.
        $connection = [System.Data.SqlClient.SqlConnection]::new("Server=admin:localhost; Database=$Database; Trusted_Connection=True; Connect Timeout=60")
        $connection.Open()

        # Creating the command and the hashset to hold the result.
        [System.Collections.Generic.HashSet[pscustomobject]]$tableList = @()
        $listingCommand = [System.Data.SqlClient.SqlCommand]::new($query, $connection)
        $listingCommand.CommandTimeout = 82800 # 23 hours.

        # Creating a reader and reading the result.
        try {
            $listingReader = $listingCommand.ExecuteReader()
            while ($listingReader.Read()) {
                [void]$tableList.Add([PSCustomObject]@{
                        ID                     = $listingReader[0]
                        TableName              = $listingReader[1]
                        CTTableName            = $listingReader[2]
                        ObjectID               = $listingReader[3]
                        CTRowCount             = $listingReader[4]
                        MinXdesID              = $listingReader[5]
                        MinTime                = $listingReader[6]
                        DaysOld                = $listingReader[7]
                        RowsBeyondRetention    = $listingReader[8]
                        AllRowsBeyondRetention = $listingReader[9]
                        NumRowsOrphaned        = $listingReader[10]
                        NumRowsDeleted         = $listingReader[11]
                        ErrorCount             = $listingReader[12]
                        ErrorNumber            = $listingReader[13]
                        CleanupTrxID           = $listingReader[14]
                        CleanupVersion         = $listingReader[15]
                    })
            }
        }
        catch {
            throw $_
        }
        finally {
            $listingCommand.Cancel()
            $listingReader.Dispose()
        }
    }
    catch {
        throw $_
    }
    finally {
        $connection.Dispose()
    }

    return $tableList
}
#endregion

$Global:logPath = "$PSScriptRoot\ChangeTrackingSideTableCleanupAsync.log"

Add-Log $Global:logPath 'Informational' '#################### ~ Starting new execution ~ ####################'

# Getting tables who have rows passed the retention period.
Add-Log $Global:logPath 'Informational' 'Getting tables that have rows beyond retention.'
Write-Verbose 'Getting tables that have rows beyond retention.'
try {
    $allCtTables = Get-CTTablesWithRowsPassedRetention($Database)

    # This value is used to cleanup the 'sys.syscommittab'.
    $Global:cleanupVersion = ($allCtTables | Select-Object -First 1).CleanupVersion
}
catch {
    Add-Log $Global:logPath 'Error' 'Error getting tables with rows beyond retention.'
    Add-Log $Global:logPath 'Error' $_.Exception.Message
    throw $_
}

# sys.syscommittab cleanup script
Add-Log $Global:logPath 'Informational' "Cleanup version: $Global:cleanupVersion."
Write-Verbose "Cleanup version: $Global:cleanupVersion."
$syscommittabCleanupScript = @"
SET NOCOUNT OFF

DECLARE @RowsDeleted BIGINT = 0;
DECLARE @TotalRowsDeleted BIGINT = 0;
DECLARE @ErrorCount INT = 0;
DECLARE @RetryCount INT = 10;

WHILE (1 = 1)
BEGIN
    SYSCOMMIT_CLEANUP_RETRY:
    BEGIN TRY
        DELETE TOP ($RowsToDeletePerIteration)
        FROM sys.syscommittab
        WHERE commit_ts <= $Global:cleanupVersion;

        SET @RowsDeleted = @@ROWCOUNT;
        SET @TotalRowsDeleted += @RowsDeleted;
        IF (@RowsDeleted < $RowsToDeletePerIteration)
        BEGIN
            SELECT @TotalRowsDeleted, 'Info';
            BREAK;
        END
    END TRY
    BEGIN CATCH
        -- 1205 is deadlock. Retry until the max retry count.
        IF (ERROR_NUMBER() = 1205)
        BEGIN
            SET @ErrorCount += 1;
            IF (@ErrorCount < @RetryCount)
            BEGIN
                WAITFOR DELAY '00:00:01'
                GOTO SYSCOMMIT_CLEANUP_RETRY;
            END
            ELSE
            BEGIN
                SELECT 'Maximum error count reached.', 'Error';
                BREAK;
            END
        END
        ELSE
        BEGIN
            -- Unexpected error occurred. We output and bail.
            SELECT ERROR_MESSAGE(), 'Error';
            BREAK;
        END
    END CATCH
END
"@

# Getting only tables that have rows passed the retention period.
$tableList = $allCtTables | Where-Object { $_.RowsBeyondRetention -gt 0 }
$currentTableCount = $tableList.Count
if (!$currentTableCount) { $currentTableCount = 0 }

if ($currentTableCount -gt 0) {
    Add-Log $Global:logPath 'Informational' "Starting table count: $currentTableCount."
    Write-Verbose "Starting table count: $currentTableCount."

    # Creating Runspace pool.
    Add-Log $Global:logPath 'Informational' 'Creating Runspace pool.'
    Write-Verbose 'Creating Runspace pool.'

    if ($MaxConcurrentTask -gt 0) {
        $Global:pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrentTask)    
    }
    else {
        $Global:pool = [runspacefactory]::CreateRunspacePool(1, $currentTableCount)
    }

    $Global:pool.ApartmentState = 'MTA'
    $Global:pool.ThreadOptions = 'UseNewThread'
    $Global:pool.Open()

    # In order for this to work in a MTA apartment our script cannot produce any output, because
    # you cannot call 'Write*' from outside the 'BeginProcessing', 'ProcessRecord', and 'EndProcessing'
    # overloads, or threads other than the main one.
    # So to catch errors, and exchange information we'll use a synchronized hashtable, which is thread safe.
    $infoStream = [hashtable]::Synchronized(@{ Log = [System.Collections.Generic.Dictionary[string, Tuple[string, bool]]]::new() })

    # The task list 
    $taskList = [System.Collections.Generic.Dictionary[string, powershell]]::new()
    
    # Creating the tasks.
    
    # Connection string that will be used by the tasks. This allows us to set a pool size big enough
    # to acomodate all tasks.
    $connectionString = "Server=localhost; Database=$Database; Trusted_Connection=True; Connect Timeout=60; Max Pool Size=$currentTableCount"

    foreach ($tableInfo in $tableList) {
        $currentTask = [powershell]::Create()
        $currentTask.RunspacePool = $Global:pool
        
        # The script that will run on each task.
        [void]$currentTask.AddScript({
                param(
                    [string]$TableName,
                    [string]$ConnectionString,
                    [hashtable]$InformationStream
                )

                try {
                    $query = @"
SET NOCOUNT OFF
DECLARE @DeletedRowCount BIGINT;

exec sys.sp_flush_CT_internal_table_on_demand '$TableName', @DeletedRowCount = @DeletedRowCount OUTPUT;

SELECT @DeletedRowCount
"@
                    
                    $connection = [System.Data.SqlClient.SqlConnection]::new($ConnectionString)
                    $connection.Open()

                    $command = [System.Data.SqlClient.SqlCommand]::new($query, $connection)
                    $command.CommandTimeout = 82800
                    $result = $command.ExecuteScalar()

                    [void]$InformationStream.Log.Add($TableName, [Tuple[string, bool]]::new("Rows deleted: $result", $false))    
                }
                catch {
                    [void]$InformationStream.Log.Add($TableName, [Tuple[string, bool]]::new($_.Exception.Message, $true))
                }
                finally {
                    $command.Cancel()
                    $connection.Dispose()
                }
    
            }).AddParameter('TableName', $tableInfo.TableName).AddParameter('ConnectionString', $connectionString).AddParameter('InformationStream', $infoStream)

        # Starting the PS instance asynchronously, and saving it on the task list.
        [void]$currentTask.BeginInvoke()
        [void]$taskList.Add($tableInfo.TableName, $currentTask)
    }

    # Creating the 'sys.syscommittab' cleanup task.
    Add-Log $Global:logPath 'Informational' "Creating the 'sys.syscommittab' cleanup task."
    Write-Verbose "Creating the 'sys.syscommittab' cleanup task."

    $syscommittabTask = [powershell]::Create()
    $syscommittabTask.RunspacePool = $Global:pool
    [void]$syscommittabTask.AddScript({

            param(
                [string]$Query,
                [string]$Database,
                [hashtable]$InformationStream
            )

            try {
                # Creating a DAC connection and command.
                $connection = [System.Data.SqlClient.SqlConnection]::new("Server=admin:localhost; Database=$Database; Trusted_Connection=True; Connect Timeout=60")
                $connection.Open()
    
                $command = [System.Data.SqlClient.SqlCommand]::new($Query, $connection)
                $command.CommandTimeout = 82800
    
                # Executing the cleanup and collecting the result.
                $reader = $command.ExecuteReader()
                if ($reader.Read()) {
                    $message = $reader[0]
                    if ($reader[1] -eq 'Error') {
                        [void]$InformationStream.Log.Add('syscommittab', [Tuple[string, bool]]::new($message, $true))
                    }
                    else {
                        [void]$InformationStream.Log.Add('syscommittab', [Tuple[string, bool]]::new("Rows deleted: $message", $false))
                    }
                }
            }
            catch {
                [void]$InformationStream.Log.Add('syscommittab', [Tuple[string, bool]]::new($_.Exception.Message, $true))
            }
            finally {
                $reader.Dispose()
                $command.Cancel()
                $connection.Dispose()
            }
        }).AddParameter('Query', $syscommittabCleanupScript).AddParameter('Database', $Database).AddParameter('InformationStream', $infoStream)

    [void]$syscommittabTask.BeginInvoke()
    [void]$taskList.Add('syscommittab', $syscommittabTask)

    # Entering the monitoring loop.
    Add-Log $Global:logPath 'Informational' 'Entering the monitoring loop.'
    Write-Verbose 'Entering the monitoring loop.'
    $loggingCount = 0
    $failedTables = [System.Collections.Generic.Dictionary[string, int]]::new()
    [System.Collections.Generic.HashSet[string]]$completedTaskNames = @()
    do {
        $completed = $true
        $runningTaskCount = 0
        foreach ($task in $taskList.Keys) {

            # Checking if the task is running.
            if ($taskList[$task].InvocationStateInfo.State -eq 'Running') {
                $completed = $false
                $runningTaskCount++
            }
            else {
                # Checking if the task has errors.
                $singleInfo = $null
                if ($infoStream.Log.TryGetValue($task, [ref]$singleInfo)) {
                    
                    # It's an error.
                    if ($singleInfo.Item2) {
                        $retryCount = $null
                        if ($failedTables.TryGetValue($task, [ref]$retryCount)) {
                            if ($retryCount -lt $MaxRetryCount) {
    
                                # Trying again.
                                Add-Log $Global:logPath 'Error' "Task for table '$($task)' failed with '$($singleInfo.Item1)'. Trying again. Retries left: $($MaxRetryCount - $failedTables[$task])."
                                Write-Warning "Task for table '$($task)' failed with '$($singleInfo.Item1)'. Trying again. Retries left: $($MaxRetryCount - $failedTables[$task])."
                            
                                $failedTables[$task]++
                                [void]$taskList[$task].BeginInvoke()
                            }
                            else {
                                # The retry count exceeds the max. Terminating this task.
                                if (!$completedTaskNames.Contains($task)) {
                                    Add-Log $Global:logPath 'Error' "Task for table '$($task)' ended with failure. Max retries exceeded."
                                    Write-Verbose "Task for table '$($task)' ended with failure. Max retries exceeded."
                                }
    
                                [void]$completedTaskNames.Add($task)
                                $taskList[$task].Dispose()
                            }
                        }
                        # First retry.
                        else {
                            if ($MaxRetryCount -gt 0) {
    
                                # Trying again.
                                Add-Log $Global:logPath 'Error' "Task for table '$($task)' failed with '$($singleInfo.Item1)'. Trying again. Retries left: $($MaxRetryCount - $failedTables[$task])."
                                Write-Warning "Task for table '$($task)' failed with '$($singleInfo.Item1)'. Trying again. Retries left: $($MaxRetryCount - $failedTables[$task])."
    
                                $failedTables.Add($task, 1)
                                [void]$taskList[$task].BeginInvoke()
                            }
                            else {
                                # No retry. Terminating this task.
                                if (!$completedTaskNames.Contains($task)) {
                                    Add-Log $Global:logPath 'Error' "Task for table '$($task)' ended with failure. Max retries exceeded."
                                    Write-Verbose "Task for table '$($task)' ended with failure. Max retries exceeded."
                                }
    
                                [void]$completedTaskNames.Add($task)
                                $taskList[$task].Dispose()
                            }
                        }
                    }
                    # It's information. 
                    else {
                        if (!$completedTaskNames.Contains($task)) {
                            Add-Log $Global:logPath 'Informational' "Task for table '$($task)' ended: '$($singleInfo.Item1)'."
                            Write-Verbose "Task for table '$($task)' ended: '$($singleInfo.Item1)'."

                            [void]$completedTaskNames.Add($task)
                            $taskList[$task].Dispose()
                        }
                    }
                }
                else {
                    # Task terminated with no errors. Disposing of it.
                    if (!$completedTaskNames.Contains($task)) {
                        Add-Log $Global:logPath 'Informational' "Task for table '$($task)' ended."
                        Write-Verbose "Task for table '$($task)' ended."

                        [void]$completedTaskNames.Add($task)
                        $taskList[$task].Dispose()
                    }
                }
            }
        }

        # Output the number of running tasks every 7 minutes.
        if ($loggingCount -ge 420) {
            if ($runningTaskCount -eq 1) { $loggingText = "1 task running." }
            else { $loggingText = "$($runningTaskCount) tasks running." }

            Add-Log $Global:logPath 'Informational' $loggingText
            Write-Verbose $loggingText
            $loggingCount = 0
        }

        Start-Sleep -Seconds 1
        $loggingCount++

    } while (!$completed)

    Write-Verbose 'No more running tasks.'
    Add-Log $Global:logPath 'Informational' 'No more running tasks.'

    # Checking again if there are tables still with rows passed retention.
    Write-Verbose 'Checking tables again for rows beyond retention.'
    Add-Log $Global:logPath 'Informational' 'Checking tables again for rows beyond retention.'
    try {
        $tableList = $null
        $tableList = Get-CTTablesWithRowsPassedRetention($Database)
    }
    catch {
        Add-Log $Global:logPath 'Error' 'Error getting tables with rows beyond retention.'
        Add-Log $Global:logPath 'Error' $_.Exception.Message
    }

    # There are still tables with rows passed retention.
    if ($tableList -and $tableList.Count -gt 0) {
        Write-Verbose "There are still $($tableList.Count) tables with rows beyond retention. Starting individual cleanup."
        Add-Log $Global:logPath 'Informational' "There are still $($tableList.Count) tables with rows beyond retention. Starting individual cleanup."

        # Ordering to start with the one with less rows beyond retention.
        $tableList = $tableList | Sort-Object -Property 'RowsBeyondRetention'
        try {

            # Creating a single DAC connection since we're cleaning tables individually.
            $connection = [System.Data.SqlClient.SqlConnection]::new("Server=admin:localhost; Database=$Database; Trusted_Connection=True; Connect Timeout=60")
            $connection.Open()

            # We're also using a single command. We change the command text for each table.
            $command = [System.Data.SqlClient.SqlCommand]::new()
            $command.Connection = $connection
            $command.CommandTimeout = 82800
            $command.CommandType = [System.Data.CommandType]::Text

            foreach ($info in $tableList) {
                Write-Verbose "Cleaning up for table '$($info.TableName)', side table '$($info.CTTableName)'."
                Add-Log $Global:logPath 'Informational' "Cleaning up for table '$($info.TableName)', side table '$($info.CTTableName)'."
            
                try {
                    $command.CommandText = @"
DECLARE @SQL NVARCHAR(MAX);

DECLARE @RowsDeleted BIGINT = 0;
DECLARE @TotalRowsDeleted BIGINT = 0;
DECLARE @ErrorCount INT = 0;
DECLARE @ErrorNumber INT = 0;
DECLARE @RetryCount INT = 10;

WHILE (1 = 1)
BEGIN

    SET @SQL = N'DELETE TOP ($RowsToDeletePerIteration) FROM sys.$($info.CTTableName) WHERE sys_change_xdes_id < $($info.CleanupTrxID)'

    SIDE_TABLE_CLEANUP_RETRY:
    BEGIN TRY
        EXEC sp_executesql @SQL;
        SET @RowsDeleted = @@ROWCOUNT;
        SET @TotalRowsDeleted += @RowsDeleted;
        IF (@RowsDeleted < $RowsToDeletePerIteration)
        BEGIN
            SELECT @TotalRowsDeleted, 'Info';
            BREAK;
        END
    END TRY
    BEGIN CATCH
        -- 1205 is deadlock. Retry until the max retry count.
        IF (ERROR_NUMBER() = 1205)
        BEGIN
            SET @ErrorCount += 1;
            IF (@ErrorCount < @RetryCount)
            BEGIN
                WAITFOR DELAY '00:00:01'
                GOTO SIDE_TABLE_CLEANUP_RETRY;
            END
            ELSE
            BEGIN
                SELECT 'Maximum error count reached.', 'Error';
                BREAK;
            END
        END
        ELSE
        BEGIN
            -- Unexpected error occurred. We output and bail.
            SELECT ERROR_MESSAGE(), 'Error';
            BREAK;
        END
    END CATCH
END
"@

                    $reader = $command.ExecuteReader()
                    if ($reader.Read()) {
                        $message = $reader[0]
                        if ($reader[1] -eq 'Error') {
                            Add-Log $Global:logPath 'Error' "Error cleaning up table '$($info.TableName)', side table '$($info.CTTableName)'."
                            Add-Log $Global:logPath 'Error' $message
                        }
                        else {
                            Write-Verbose "Finished cleaning up for '$($info.TableName)'. Rows deleted: $message."
                            Add-Log $Global:logPath 'Informational' "Finished cleaning up for '$($info.TableName)'. Rows deleted: $message."
                        }
                    }
                }
                catch {
                    Add-Log $Global:logPath 'Error' "Error cleaning up table '$($info.TableName)', side table '$($info.CTTableName)'."
                    Add-Log $Global:logPath 'Error' $_.Exception.Message
                }
                finally {
                    $reader.Dispose()
                }
            }
        }
        catch {
            Add-Log $Global:logPath 'Error' 'Error cleaning up individual tables.'
            Add-Log $Global:logPath 'Error' $_.Exception.Message
        }
        finally {
            $command.Cancel()
            $connection.Dispose()
        }

        Write-Verbose 'Finished individual table cleanup.'
        Add-Log $Global:logPath 'Informational' 'Finished individual table cleanup.'
    }
    else {
        Write-Verbose 'No more tables with row passed retention.'
        Add-Log $Global:logPath 'Informational' 'No more tables with row passed retention.'
    }

    Write-Verbose 'Disposing of resources.'
    try { $Global:pool.Dispose() }
    catch { }
}
else {
    Write-Verbose 'There are no tables with rows passed the retention period.'
    Add-Log $Global:logPath 'Informational' 'There are no tables with rows passed the retention period.'

    # sys.syscommittab cleanup.
    Write-Verbose "Starting the 'syscommittab' table cleanup."
    Add-Log $Global:logPath 'Informational' "Starting the 'syscommittab' table cleanup."
    try {
        # Creating a DAC connection and command.
        $connection = [System.Data.SqlClient.SqlConnection]::new("Server=admin:localhost; Database=$Database; Trusted_Connection=True; Connect Timeout=60")
        $connection.Open()

        $command = [System.Data.SqlClient.SqlCommand]::new($syscommittabCleanupScript, $connection)
        $command.CommandTimeout = 82800

        # Executing the cleanup.
        $reader = $command.ExecuteReader()
        if ($reader.Read()) {
            $message = $reader[0]
            if ($reader[1] -eq 'Error') {
                Add-Log $Global:logPath 'Error' "Error cleaning up table 'syscommittab'."
                Add-Log $Global:logPath 'Error' $message
            }
            else {
                Write-Verbose "Finished cleaning up of 'syscommittab'. Rows deleted: $message."
                Add-Log $Global:logPath 'Informational' "Finished cleaning up of 'syscommittab'. Rows deleted: $message."
            }
        }
    }
    catch {
        Add-Log $Global:logPath 'Error' "Error cleaning up the 'syscommittab' table."
        Add-Log $Global:logPath 'Error' $_.Exception.Message
    }
    finally {
        $reader.Dispose()
        $command.Cancel()
        $connection.Dispose()
    }
}

Add-Log $Global:logPath 'Informational' 'End of execution.'
Write-Verbose 'End of execution.'