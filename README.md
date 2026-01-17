# 🛡️ VirtuLens - VMware Audit Collector

> **Secure, Read-Only, and Privacy-First audit collector for VMware vSphere infrastructures.**

Ce script est conçu pour auditer la santé, la sécurité et la configuration de votre infrastructure VMware sans aucun risque.

## 🔒 Sécurité & Confidentialité
* **100% Lecture Seule (Read-Only) :** Utilise uniquement des commandes `Get-`. Aucune modification n'est possible.
* **Anonymisation Locale :** Les noms de vos serveurs (VMs, Hôtes, Datastores) sont hachés/anonymisés **avant** la création du fichier d'export.
* **Code Open Source :** Le code est transparent et vérifiable par vos équipes de sécurité.

## 🚀 Comment l'utiliser ?

### Prérequis
* Un poste avec accès réseau au vCenter.
* PowerShell 5.1 ou plus récent.
* Module VMware PowerCLI (Installé automatiquement si manquant, ou à installer via `Install-Module VMware.PowerCLI`).

### Instructions
1.  Téléchargez le fichier `Get-AuditData.ps1` (Cliquez sur le fichier > Download raw file).
2.  Ouvrez PowerShell en tant qu'Administrateur.
3.  Lancez le script :
    ```powershell
    .\Get-AuditData.ps1
    ```
4.  Entrez l'adresse IP de votre vCenter et vos identifiants (Lecture seule suffit).

### 📂 Résultats
Le script génère deux fichiers dans le même dossier :
1.  `Audit_Data_Anon_xxxx.json` : **Le fichier à nous envoyer.** (Données techniques anonymisées).
2.  `Mapping_Key_DO_NOT_SEND_xxxx.csv` : **Le fichier à CONSERVER.** (Table de correspondance pour vous seul).

---
**License :** MIT License.
**Author :** VirtuLens Engineering.
