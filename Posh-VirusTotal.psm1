
#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTAPIKey
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
function Get-VTIPReport
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
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'ip'= $IPAddress; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
        $IPReport
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTDomainReport
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
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/domain/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'domain'= $Domain; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        
        $DomainReport = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        $DomainReport.pstypenames.insert(0,'VirusTotal.Domain.Report')
        $DomainReport
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileReport
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
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ","

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body =  @{'resource'= $QueryResources; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }


        $ReportResult =Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        foreach ($FileReport in $ReportResult)
        {
            $FileReport.pstypenames.insert(0,'VirusTotal.File.Report')
            $FileReport
        }
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTURLReport
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
        [switch]$Scan,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
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
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ","

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'resource'= $QueryResources; 'apikey'= $APIKey; 'scan'=$scanurl}


        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $ReportResult = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        foreach ($URLReport in $ReportResult)
        {
            $URLReport.pstypenames.insert(0,'VirusTotal.URL.Report')
            $URLReport
        }
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VTURL
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
        [switch]$Scan,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
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
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $URLList =  $URL -join "`n"
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Body =  @{'url'= $URLList; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $SubmitedList = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        foreach($submited in $SubmitedList)
        {
            $submited.pstypenames.insert(0,'VirusTotal.URL.Submission')
            $submited
        }
      
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VTFile
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
        #$req.Headers = $headers
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

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-PoshVTVersion
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
            InstalledVersion = "$($installed.Version)"
            CurrentVersion   = $currentversion
        }
        New-Object -TypeName psobject -Property $props
     }
     End
     {
          
     }
 }

#  .ExternalHelp Posh-VirusTotal.Help.xml
 function Get-VTAPIKeyInfo
{
    [CmdletBinding()]
    Param
    (

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'http://www.virustotal.com/vtapi/v2/key/details'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
        $IPReport
        
    }
    End
    {
    }
}


# Private API
###############


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTSpecialURL
{
    [CmdletBinding()]
    Param
    (
        # VirusToral Private API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        
        $URI = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verifies as a Private API Key.'
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'apikey' = $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $IPReport = Invoke-RestMethod $Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.SpecialUploadURL')
        $IPReport
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileComment
{
    [CmdletBinding()]
    Param
    (
        # File MD5, SHA1 or SHA256 Checksum to get comments from.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/comments/get'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verifies as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('resource',$Resource)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                Write-Error "API key is not valid." -ErrorAction Stop
            }
            elseif ($RESTError.Message -like "*204*")
            {
                Write-Error "API key rate has been reached." -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }
        $Response.pstypenames.insert(0,'VirusTotal.Comment')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTFileComment
{
    [CmdletBinding()]
    Param
    (
        # File MD5, SHA1 or SHA256 Checksum to comment on.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        [Parameter(Mandatory=$true)]
        [string]$Comment,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/comments/put'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verifies as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('resource',$Resource)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }
        $Response.pstypenames.insert(0,'VirusTotal.Comment')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTFileRescan
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # Date in which the rescan should be performed. If not specified the rescan will be performed immediately.
        [Parameter(Mandatory=$false)]
        [datetime]$Date,

        # Period in days in which the file should be rescanned.
        [Parameter(Mandatory=$false)]
        [int32]$Period,

        # Used in conjunction with period to specify the number of times the file should be rescanned.
        [Parameter(Mandatory=$false)]
        [int32]$Repeat,

        # An URL where a POST notification should be sent when the rescan finishes.
        [Parameter(Mandatory=$false)]
        [string]$NotifyURL,

        # Indicates if POST notifications should be sent only if the scan results differ from the previous one.
        [Parameter(Mandatory=$false)]
        [bool]$NotifyChanges,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey'= $APIKey}

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verifies as a Private API Key.'
    }
    Process
    {
        $Body.add('resource',$Resource)
        if ($Date)
        {
            $Body.add('date', ($Date.ToString("yyyyMMddhhmmss")))
        }

        if ($Period)
        {
            $Body.add('period', $Period)
        }

        if ($Repeat)
        {
            $Body.add('repeat', $Repeat)
        }

        if ($NotifyURL)
        {
            $Body.add('notify_url', $NotifyURL)
        }

        if ($NotifyChanges)
        {
            $Body.add('notify_changes_only', $NotifyChanges)
        }

        $Body.add('resource',$Resource)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }

        $Response.pstypenames.insert(0,'VirusTotal.ReScan')
        $Response
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Remove-VTFileRescan
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to remove rescan.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/rescan/delete'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey'= $APIKey}

        

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verifies as a Private API Key.'

    }
    Process
    {

        $Body.add('resource',$Resource)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                Write-Error "API key is not valid." -ErrorAction Stop
            }
            elseif ($RESTError.Message -like "*204*")
            {
                Write-Error "API key rate has been reached." -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }

        $Response.pstypenames.insert(0,'VirusTotal.ReScan')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileScanReport
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID of the scan.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [switch]$AllInfo,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey'= $APIKey}

        if ($AllInfo)
        {
            $Body.Add('allinfo',1)
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verified as a Private API Key.'
    }
    Process
    {

        $Body.add('resource',$Resource)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                Write-Error "API key is not valid." -ErrorAction Stop
            }
            elseif ($RESTError.Message -like "*204*")
            {
                Write-Error "API key rate has been reached." -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }
        $Response.pstypenames.insert(0,'VirusTotal.Scan.Report')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileBehaviourReport
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum of file.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # File name and path to save Behaviour report as a Cuckoo JSON Dump.
        [Parameter(Mandatory=$true,
                   Position=1)]
        [string]$Report,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials

    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/behaviour'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('hash',$Resource)

        $ReportFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Report)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('Outfile', $ReportFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Verbose "Saving report to $($ReportFullPath)."

        $bahaviour_report = Invoke-WebRequest @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileSample
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum of file.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # File name and path to save sample.
        [Parameter(Mandatory=$true,
                   Position=1)]
        [string]$File,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/download'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('hash',$Resource)

        $SampleFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('OutFile', $SampleFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Verbose "Saving report to $($SampleFullPath)."

        $SampleResponse = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileNetworkTraffic
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Hash,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # File name and path to save Network Traffic in PCAP format.
        [Parameter(Mandatory=$true,
                   Position=1)]
        [string]$File,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials

    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/network-traffic'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('hash',$Resource)

        $NTFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('OutFile', $NTFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        

        Write-Verbose "Saving file to $($NTFullPath)."

        $NTResponse = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                throw "API key is not valid."
            }
            elseif ($RESTError.Message -like "*204*")
            {
                throw "API key rate has been reached."
            }
            else
            {
                throw $RESTError
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Search-VTAdvancedReversed
{
    [CmdletBinding()]
    Param
    (
        # A search modifier compliant file search query..
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Query,

        # VirusToral API Key.
        [Parameter(Mandatory=$false)]
        [string]$APIKey,

        # The offset value returned by a previously issued identical query.
        [Parameter(Mandatory=$false)]
        [int]$OffSet,

        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,
 
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/vtapi/v2/file/search'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error "No VirusTotal API Key has been specified or set."
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey' = $APIKey
                'query' = $Query}
        # If an offset is provided apply it.
        if ($OffSet)
        {
            $Body.Add('offset',$OffSet)
        }
        
        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw "The key provided is not a Private API Key"
        }
        Write-Verbose 'Key verifies as a Private API Key.'

    }
    Process
    {

        $Body.add('resource',$Resource)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq "Proxy")
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains("403"))
            {
                Write-Error "API key is not valid." -ErrorAction Stop
            }
            elseif ($RESTError.Message -like "*204*")
            {
                Write-Error "API key rate has been reached." -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }

        $Response.pstypenames.insert(0,'VirusTotal.Search')
        $Response

    }
    End
    {
    }
}
