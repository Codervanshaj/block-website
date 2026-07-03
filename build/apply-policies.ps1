$ErrorActionPreference = 'Stop'

New-Item -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Force | Out-Null
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'ProxyServer' -ErrorAction SilentlyContinue

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'ProxyServer' -ErrorAction SilentlyContinue

New-Item -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Force | Out-Null
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Name 'ProxyServer' -ErrorAction SilentlyContinue

New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Force | Out-Null
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxyEnable' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxyServer' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoConfigURL' -ErrorAction SilentlyContinue

New-Item -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'IncognitoModeAvailability' -PropertyType DWord -Value 1 -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'ProxyMode' -PropertyType String -Value 'pac_script' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'ProxyPacUrl' -PropertyType String -Value 'file:///D:/prevent-visit/build/prevent-visit.pac' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'DnsOverHttpsMode' -PropertyType String -Value 'off' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'InPrivateModeAvailability' -PropertyType DWord -Value 1 -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'ProxyMode' -PropertyType String -Value 'pac_script' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'ProxyPacUrl' -PropertyType String -Value 'file:///D:/prevent-visit/build/prevent-visit.pac' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DnsOverHttpsMode' -PropertyType String -Value 'off' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Name 'IncognitoModeAvailability' -PropertyType DWord -Value 1 -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Name 'ProxyMode' -PropertyType String -Value 'pac_script' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Name 'ProxyPacUrl' -PropertyType String -Value 'file:///D:/prevent-visit/build/prevent-visit.pac' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' -Name 'DnsOverHttpsMode' -PropertyType String -Value 'off' -Force | Out-Null

New-Item -Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' -Name 'DisablePrivateBrowsing' -PropertyType DWord -Value 1 -Force | Out-Null
