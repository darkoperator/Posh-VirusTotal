
#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VirusTotalAPIKey
{
    [CmdletBinding()]
    Param
    (
        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
    }
    Process
    {
        $Global:VTAPIKey = $APIKey
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VirusTotalIPReport
{
    [CmdletBinding()]
    Param
    (
        # IP Address to scan for.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$IPAddress,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        Try
        {
            $IPReport = Invoke-RestMethod -Uri $URI -method get -Body @{'ip'= $IPAddress; 'apikey'= $APIKey}
            $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
            $IPReport
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VirusTotalDomainReport
{
    [CmdletBinding()]
    Param
    (
        # Domain to scan.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Domain,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/domain/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        Try
        {
            $DomainReport = Invoke-RestMethod -Uri $URI -method get -Body @{'domain'= $Domain; 'apikey'= $APIKey}
            $DomainReport.pstypenames.insert(0,'VirusTotal.Domain.Report')
            $DomainReport
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VirusTotalFileReport
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateCount(1,4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ","

        Try
        {
            $ReportResult =Invoke-RestMethod -Uri $URI -method get -Body @{'resource'= $QueryResources; 'apikey'= $APIKey}
            foreach ($FileReport in $ReportResult)
            {
                $FileReport.pstypenames.insert(0,'VirusTotal.File.Report')
                $FileReport
            }
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VirusTotalURLReport
{
    [CmdletBinding()]
    Param
    (
        # URL or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateCount(1,4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(Mandatory=$false)]
        [switch]$Scan
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/report'
        
        if ($Scan)
        {
            $scanurl = 1
        }
        else
        {
            $scanurl = 0
        }

        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ","

        Try
        {
            $ReportResult = Invoke-RestMethod -Uri $URI -method get -Body @{'resource'= $QueryResources; 'apikey'= $APIKey; 'scan'=$scanurl}
            foreach ($URLReport in $ReportResult)
            {
                $URLReport.pstypenames.insert(0,'VirusTotal.URL.Report')
                $URLReport
            }
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VirusTotalURL
{
    [CmdletBinding()]
    Param
    (
        # URL or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateCount(1,4)]
        [string[]]$URL,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(Mandatory=$false)]
        [switch]$Scan
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/scan'
        if ($Scan)
        {
            $scanurl = 1
        }
        else
        {
            $scanurl = 0
        }

        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $URLList =  $URL -join "`n"

        Try
        {
            $SubmitedList = Invoke-RestMethod -Uri $URI -method Post -Body @{'url'= $URLList; 'apikey'= $APIKey}
            foreach($submited in $SubmitedList)
            {
                $submited.pstypenames.insert(0,'VirusTotal.URL.Submission')
                $submited
            }
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VirusTotalFile
{
    [CmdletBinding()]
    Param
    (
        # URL or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$File,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey
    )

    Begin
    {
        $URI = "http://www.virustotal.com/vtapi/v2/file/scan"

        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $fileinfo = Get-ItemProperty -Path $File

        # Check the file size
        if ($fileinfo.length -gt 64mb)
        {
            Write-Error "VirusTotal has a limit of 64MB per file submited" -ErrorAction Stop
        }
   
        $req = [System.Net.httpWebRequest][System.Net.WebRequest]::Create("http://www.virustotal.com/vtapi/v2/file/scan")
        $req.Headers = $headers
        $req.Method = "POST"
        $req.AllowWriteStreamBuffering = $true;
        $req.SendChunked = $false;
        $req.KeepAlive = $true;

        $headers = New-Object -TypeName System.Net.WebHeaderCollection

        # Prep the POST Headers for the message
        $headers.add("apikey",$apikey)
        $boundary = "----------------------------" + [DateTime]::Now.Ticks.ToString("x")
        $req.ContentType = "multipart/form-data; boundary=" + $boundary
        [byte[]]$boundarybytes = [System.Text.Encoding]::ASCII.GetBytes("`r`n--" + $boundary + "`r`n")
        [string]$formdataTemplate = "`r`n--" + $boundary + "`r`nContent-Disposition: form-data; name=`"{0}`";`r`n`r`n{1}"
        [string]$formitem = [string]::Format($formdataTemplate, "apikey", $apikey)
        [byte[]]$formitembytes = [System.Text.Encoding]::UTF8.GetBytes($formitem)
        [string]$headerTemplate = "Content-Disposition: form-data; name=`"{0}`"; filename=`"{1}`"`r`nContent-Type: application/octet-stream`r`n`r`n"
        [string]$header = [string]::Format($headerTemplate, "file", (get-item $file).name)
        [byte[]]$headerbytes = [System.Text.Encoding]::UTF8.GetBytes($header)
        [string]$footerTemplate = "Content-Disposition: form-data; name=`"Upload`"`r`n`r`nSubmit Query`r`n" + $boundary + "--"
        [byte[]]$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerTemplate)


        # Read the file and format the message
        $stream = $req.GetRequestStream()
        $rdr = new-object System.IO.FileStream($fileinfo.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        [byte[]]$buffer = new-object byte[] $rdr.Length
        [int]$total = [int]$count = 0
        $stream.Write($formitembytes, 0, $formitembytes.Length)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($headerbytes, 0,$headerbytes.Length)
        $count = $rdr.Read($buffer, 0, $buffer.Length)
        do{
            $stream.Write($buffer, 0, $count)
            $count = $rdr.Read($buffer, 0, $buffer.Length)
        }while ($count > 0)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($footerBytes, 0, $footerBytes.Length)
        $stream.close()

        Try
        {
            # Upload the file
            $response = $req.GetResponse()

            # Read the response
            $respstream = $response.GetResponseStream()
            $sr = new-object System.IO.StreamReader $respstream
            $result = $sr.ReadToEnd()
            ConvertFrom-Json $result
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}

function Get-PoshVirusTotalVersion
 {
     [CmdletBinding(DefaultParameterSetName="Index")]
     [OutputType([pscustomobject])]
     Param
     ()
 
     Begin
     {
        $currentversion = ""
        $installed = Get-Module -Name "Posh-VirusTotal" 
     }
     Process
     {
        $webClient = New-Object System.Net.WebClient
        Try
        {
            $current = Invoke-Expression  $webClient.DownloadString('https://raw.github.com/darkoperator/Posh-VirusTotal/master/Posh-VirusTotal.psd1')
            $currentversion = $current.moduleversion
        }
        Catch
        {
            Write-Warning "Could not retrieve the current version."
        }
        $majorver,$minorver = $currentversion.split(".")

        if ($majorver -gt $installed.Version.Major)
        {
            Write-Warning "You are running an outdated version of the module."
        }
        elseif ($minorver -gt $installed.Version.Minor)
        {
            Write-Warning "You are running an outdated version of the module."
        } 
        
        $props = @{
            InstalledVersion = $installed.Version.ToString()
            CurrentVersion   = $currentversion
        }
        New-Object -TypeName psobject -Property $props
     }
     End
     {
          
     }
 }