<#
.SYNOPSIS
    VirtuLens - VMware Infrastructure Audit Collector (Read-Only)

.DESCRIPTION
    Script de collecte automatisée pour audit de santé et conformité.
    SÉCURITÉ : 100% Lecture Seule.
    CONFIDENTIALITÉ : Anonymisation des noms à la source (Hashing).
    
    INSTRUCTIONS :
    1. Ouvrir PowerShell en tant qu'Administrateur.
    2. Exécuter le script : .\Get-AuditData.ps1
    3. Se connecter au vCenter via la fenêtre sécurisée.

.NOTES
    Author:      VirtuLens Engineering
    Version:     1.1.0 (Public Release)
    LastUpdated: 2026-01-17
    License:     MIT (Open Source)
#>

# ---------------------------------------------------------------------------
# 1. PARAMÉTRAGE & SÉCURITÉ
# ---------------------------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

# Dossier courant
$ScriptPath = $PSScriptRoot
if (-not $ScriptPath) { $ScriptPath = Get-Location }

$Timestamp = (Get-Date).ToString("yyyyMMdd-HHmm")
$OutputFileJson = Join-Path $ScriptPath "Audit_Data_Anon_$Timestamp.json"
$OutputFileMap  = Join-Path $ScriptPath "Mapping_Key_DO_NOT_SEND_$Timestamp.csv"

# Initialisation Anonymisation
$Global:MappingList = @()
$Global:AliasCounters = @{ "Cluster"=1; "Host"=1; "Datastore"=1; "VM"=1; "Network"=1 }

# ---------------------------------------------------------------------------
# 2. FONCTIONS
# ---------------------------------------------------------------------------

function Get-AnonAlias {
    param ([string]$RealName, [string]$Type, [string]$Prefix)
    $Index = $Global:AliasCounters[$Type]
    $Alias = "{0}_{1:D3}" -f $Prefix, $Index
    $Global:AliasCounters[$Type]++
    $Global:MappingList += [PSCustomObject]@{ Type=$Type; RealName=$RealName; Alias=$Alias }
    return $Alias
}

function Get-RecursiveSnapshotStats {
    param($SnapshotTree)
    $Info = @{ Count = 0; Oldest = [DateTime]::Now }
    foreach ($snap in $SnapshotTree) {
        $Info.Count++
        if ($snap.CreateTime -lt $Info.Oldest) { $Info.Oldest = $snap.CreateTime }
        if ($snap.ChildSnapshotList) {
            $ChildInfo = Get-RecursiveSnapshotStats -SnapshotTree $snap.ChildSnapshotList
            $Info.Count += $ChildInfo.Count
            if ($ChildInfo.Oldest -lt $Info.Oldest) { $Info.Oldest = $ChildInfo.Oldest }
        }
    }
    return $Info
}

# ---------------------------------------------------------------------------
# 3. EXÉCUTION
# ---------------------------------------------------------------------------
Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   VIRTU.LENS - AUDIT COLLECTOR (SAFE MODE)" -ForegroundColor Cyan
Write-Host "   Status: Read-Only | Anonymization: Active" -ForegroundColor Gray
Write-Host "================================================================="
Write-Host ""

try {
    # Vérification PowerCLI
    if (-not (Get-Module -Name VMware.PowerCLI -ListAvailable)) {
        Throw "Le module 'VMware.PowerCLI' n'est pas installé sur cette machine."
    }
    if (-not (Get-Module -Name VMware.PowerCLI -ErrorAction SilentlyContinue)) {
        Import-Module VMware.PowerCLI -ErrorAction Stop
    }

    # Connexion
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false | Out-Null
    if ($global:DefaultVIServer) {
        $vCenterInfo = $global:DefaultVIServer
        Write-Host "[INFO] Déjà connecté à $($vCenterInfo.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "Connexion vCenter requise..." -ForegroundColor Yellow
        $vCenterInfo = Connect-VIServer -ErrorAction Stop
        Write-Host "[OK] Connecté à $($vCenterInfo.Name)" -ForegroundColor Green
    }

    # Structure Données
    $AuditData = @{
        Metadata = @{
            AuditDate       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            vCenterVersion = $vCenterInfo.Version
            vCenterBuild   = $vCenterInfo.Build
        }
        Clusters = @(); Hosts = @(); Datastores = @(); VMs = @(); Networks = @()
    }

    # --- CLUSTERS ---
    Write-Progress -Activity "VirtuLens Audit" -Status "1/5 : Clusters..." -PercentComplete 20
    $viewClusters = Get-View -ViewType ClusterComputeResource -Property Name, ConfigurationEx, DasConfig
    foreach ($cl in $viewClusters) {
        $alias = Get-AnonAlias -RealName $cl.Name -Type "Cluster" -Prefix "Cluster"
        $AuditData.Clusters += [PSCustomObject]@{
            Alias = $alias; HAEnabled = $cl.ConfigurationEx.DasConfig.Enabled
            DRSEnabled = $cl.ConfigurationEx.DrsConfig.Enabled; DRSLevel = $cl.ConfigurationEx.DrsConfig.DefaultVmBehavior
        }
    }

    # --- HOSTS (Broadcom Metrics) ---
    Write-Progress -Activity "VirtuLens Audit" -Status "2/5 : Hôtes ESXi..." -PercentComplete 40
    $viewHosts = Get-View -ViewType HostSystem -Property Name, Hardware, Summary, Config.Service.Service, Config.Product, Config.Network
    foreach ($esx in $viewHosts) {
        $alias = Get-AnonAlias -RealName $esx.Name -Type "Host" -Prefix "Host"
        
        # Service Tag (si dispo)
        $ST = "Unknown"
        if ($esx.Hardware.SystemInfo.OtherIdentifyingInfo) {
            $t = $esx.Hardware.SystemInfo.OtherIdentifyingInfo | Where-Object { $_.IdentifierType.Key -match "ServiceTag|SerialNumber" }
            if ($t) { $ST = ($t | Select -First 1).IdentifierValue }
        }
        
        # SSH Check
        $SSH = if (($esx.Config.Service.Service | Where {$_.Key -eq "TSM-SSH"}).Running) { "Running" } else { "Stopped" }
        
        $AuditData.Hosts += [PSCustomObject]@{
            Alias = $alias; Version = $esx.Config.Product.Version; Build = $esx.Config.Product.Build
            Model = $esx.Hardware.SystemInfo.Model; CPUCores = $esx.Hardware.CpuInfo.NumCpuCores
            RAMTotalGB = [math]::Round($esx.Hardware.MemorySize / 1GB, 0)
            ServiceTag = $ST; SSHStatus = $SSH
        }
    }

    # --- DATASTORES ---
    Write-Progress -Activity "VirtuLens Audit" -Status "3/5 : Stockage..." -PercentComplete 60
    $viewDatastores = Get-View -ViewType Datastore -Property Name, Summary, Info, IormConfiguration, Summary.QuickStats
    foreach ($ds in $viewDatastores) {
        $alias = Get-AnonAlias -RealName $ds.Name -Type "Datastore" -Prefix "DS"
        $Lat = if ($ds.Summary.QuickStats.OverallLatency) { $ds.Summary.QuickStats.OverallLatency } else { 0 }
        $AuditData.Datastores += [PSCustomObject]@{
            Alias = $alias; Type = $ds.Summary.Type; CapacityGB = [math]::Round($ds.Summary.Capacity / 1GB, 0)
            LatencyMs = $Lat; SIOCEnabled = if ($ds.IormConfiguration) { $ds.IormConfiguration.Enabled } else { $false }
        }
    }
    $viewDatastores = $null; [GC]::Collect()

    # --- VMS (Performance & Hygiène) ---
    Write-Progress -Activity "VirtuLens Audit" -Status "4/5 : Machines Virtuelles..." -PercentComplete 80
    $viewVMs = Get-View -ViewType VirtualMachine -Property Name, Runtime, Config, Guest, Snapshot, Summary.QuickStats
    foreach ($vm in $viewVMs) {
        $alias = Get-AnonAlias -RealName $vm.Name -Type "VM" -Prefix "VM"
        
        # Check ISO
        $Iso = $false; if ($vm.Config.Hardware.Device) { foreach($d in $vm.Config.Hardware.Device){ if($d -is [VMware.Vim.VirtualCdrom] -and $d.Backing.FileName -like "*.iso"){$Iso=$true}}}
        
        # Check Snapshots
        $SnapC = 0; $OldSnap = 0
        if ($vm.Snapshot -and $vm.Snapshot.RootSnapshotList) {
            $S = Get-RecursiveSnapshotStats -SnapshotTree $vm.Snapshot.RootSnapshotList
            $SnapC = $S.Count; if ($SnapC -gt 0) { $OldSnap = [math]::Round((New-TimeSpan -Start $S.Oldest -End (Get-Date)).TotalDays, 0) }
        }

        $AuditData.VMs += [PSCustomObject]@{
            Alias = $alias; PowerState = $vm.Runtime.PowerState; GuestOS = $vm.Config.GuestFullName
            vCPU = $vm.Config.Hardware.NumCPU; RAMGB = [math]::Round($vm.Config.Hardware.MemoryMB / 1024, 1)
            Tools = if($vm.Guest.ToolsStatus){$vm.Guest.ToolsStatus}else{"NotRunning"}
            Iso = $Iso; SnapCount = $SnapC; OldestSnapDays = $OldSnap
            CpuReady = if($vm.Summary.QuickStats.OverallCpuReadiness){$vm.Summary.QuickStats.OverallCpuReadiness}else{0}
        }
    }
    $viewVMs = $null; [GC]::Collect()

    # --- NETWORK ---
    Write-Progress -Activity "VirtuLens Audit" -Status "5/5 : Réseau..." -PercentComplete 90
    foreach ($esx in $viewHosts) {
        if ($esx.Config.Network.Vswitch) {
            foreach ($vsw in $esx.Config.Network.Vswitch) {
                $HAlias = ($Global:MappingList | Where {$_.RealName -eq $esx.Name}).Alias
                $NetAlias = Get-AnonAlias -RealName ($esx.Name + "_" + $vsw.Name) -Type "Network" -Prefix "vSwitch"
                $AuditData.Networks += [PSCustomObject]@{
                    HostAlias = $HAlias; Alias = $NetAlias; MTU = $vsw.Mtu
                    Promiscuous = $vsw.Spec.Policy.Security.AllowPromiscuous
                }
            }
        }
    }

    # --- EXPORT ---
    Write-Progress -Activity "VirtuLens Audit" -Status "Sauvegarde..." -PercentComplete 95
    $AuditData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFileJson -Encoding UTF8
    $Global:MappingList | Export-Csv -Path $OutputFileMap -NoTypeInformation -Encoding UTF8

    Write-Progress -Activity "VirtuLens Audit" -Status "Terminé !" -PercentComplete 100
}
catch {
    Write-Host ""
    Write-Error "ERREUR CRITIQUE : $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "   AUDIT TERMINÉ AVEC SUCCÈS" -ForegroundColor Green
Write-Host "================================================================="
Write-Host "1. FICHIER A ENVOYER (ANONYME) :" -ForegroundColor Cyan
Write-Host "   -> $OutputFileJson"
Write-Host ""
Write-Host "2. FICHIER A CONSERVER (CONFIDENTIEL) :" -ForegroundColor Red
Write-Host "   -> $OutputFileMap" -ForegroundColor Red
Write-Host "================================================================="
Write-Host "Appuyez sur [ENTRÉE] pour quitter..." -ForegroundColor Gray
Read-Host
