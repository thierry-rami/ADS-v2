## je  Vérifie si Active Directory est installé
#$adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).Installed
# Si Active Directory n'est pas installé, je l'installe
#if (-not $adInstalled) {
#    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
#}
## Vérifier si le domaine existe déjà
#$domainExists = (Get-ADDomain -ErrorAction SilentlyContinue) -ne $null
## Si le domaine n'existe pas, je le crée
#if (-not $domainExists) {
#    $domainName = "pourlesvieux.local"
     $safeModePassword = ConvertTo-SecureString -AsPlainText "Azerty06!" -Force
#    Install-ADDSForest -DomainName $domainName -SafeModeAdministratorPassword $safeModePassword -Force -Confirm:$false
#}

# je recupere le SID de l'admin du domaine 
# Récupérer le SID du groupe "Admins du domaine"
$domainAdminsGroup = Get-ADGroup -Filter {Name -eq "Admins du domaine"}
if ($domainAdminsGroup) {
    $domainAdminsSID = $domainAdminsGroup.SID
} else {
    Write-Warning "Le groupe 'Admins du domaine' n'a pas été trouvé."
}


# Durée de validité du mot de passe en jours pour les utilisateurs non CADRES (90 jours)
$maxPasswordAgeNonCadres =  (Get-Date).AddDays(90)
# Durée de validité du mot de passe en jours pour les utilisateurs CADRES (60 jours)
$maxPasswordAgeCadres = (Get-Date).AddDays(90)

# Importer les données du fichier CSV pour les utilisateurs
$utilisateurs = Import-Csv -Path "Utilisateur_ads_v2.csv" -Encoding UTF8





# Créer un tableau unique des établissements
$etablissements = $utilisateurs | Select-Object -ExpandProperty ETABLISSEMENT -Unique

# Parcourir chaque établissement et créer la structure correspondante dans Active Directory
foreach ($etablissement in $etablissements) {
    # Créer l'unité organisationnelle pour l'établissement
    New-ADOrganizationalUnit -Name $etablissement.ToUpper() -Path "DC=pourlesvieux,DC=local" -Description "Unité organisationnelle pour $etablissement"

    # Créer les sous-unités organisationnelles (Computers, Groupes, Utilisateurs) dans chaque OU principale
    $subOUs = "Computers", "Groupes", "Utilisateurs"
    foreach ($subOU in $subOUs) {
        New-ADOrganizationalUnit -Name $subOU -Path "OU=$etablissement,DC=pourlesvieux,DC=local" -Description "Sous-OU pour $subOU dans $etablissement"
    }
}

foreach ($utilisateur in $utilisateurs) 
{
    $nom = $utilisateur.NOM
    $prenom = $utilisateur.PRENOM
    $etablissement = $utilisateur.ETABLISSEMENT
    $fonctions = $utilisateur.FONCTION -split "-"

    # Créer le nom d'utilisateur
    $username = $prenom.ToLower() +"."+ $nom.ToLower()
    # mot de passe initial)
    $password = ConvertTo-SecureString -String "Azerty06!" -AsPlainText -Force
    #utilisateur est membre de CADRES ?
      $isCadre = $fonctions -contains "cadres"
    # Durée de validité du mot de pass
    if ($isCadre) {
        $maxPasswordAge = $maxPasswordAgeCadres
    } else {
        $maxPasswordAge = $maxPasswordAgeNonCadres
    }
$userFolderPath = "\\pdc-vieux\SRV\UserShare\$username"
$localuserFolderPath = "C:\SRV\UserShare\$username"

    # Créer le compte utilisateur
    $userParams = @{
        Name                = "$prenom $nom"
        SamAccountName      =  $username
        UserPrincipalName   = "$username@pourlesvieux.local"
        GivenName           =  $prenom
        Surname             =  $nom
        AccountPassword     =  $password
        Enabled             =  $true
        Path                =  "OU=Utilisateurs,OU=$etablissement,DC=pourlesvieux,DC=local"
        HomeDirectory       =  $userFolderPath ## "\\pdc-vieux\SRV\UserShare\$username”  # \$etablissement\$username
        HomeDrive           =  "U:"
        Description         =  "Compte utilisateur pour $prenom $nom"
        ChangePasswordAtLogon = $false  #  force le changement de mot de passe à la première connexion
 #      PasswordNeverExpires = $true  # Le mot de passe expire 
 #      AccountExpirationDate  = $maxPasswordAge  # Durée de validité du mot de passe
   
    }
    New-ADUser @userParams | Out-Null

    # maintenant creation du homedir de l'itilisateur
    if (-not (Test-Path $localuserFolderPath)) 
    {
        New-Item -Path $localuserFolderPath -ItemType Directory | Out-Null
        # Récupérer le SID de l'utilisateur
        $userSID = (Get-ADUser -Identity $username).SID
        # Autorisations sur le dossier utilisateur
        $acl = Get-Acl $localuserFolderPath
        $acl.SetAccessRuleProtection($true, $false) # Empêcher l'héritage des autorisations
        # règle d'accès pour l'administrateur du domaine
        $ruleDomainAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule($domainAdminsSID, "FullControl", "Allow")
        $acl.AddAccessRule($ruleDomainAdmins)
        # règle d'accès pour l'utilisateur
        $ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule($userSID, "FullControl", "Allow")
        $acl.AddAccessRule($ruleUser)
        Set-Acl $localuserFolderPath $acl
    }

    # Créer les noms de groupe en utilisant les trois premières lettres de l'établissement suivi de "-" et de la fonction
    $groupPrefix = $etablissement.Substring(0,3).ToUpper() + "-"
    $ouPath = "OU=Groupes,OU=$etablissement,DC=pourlesvieux,DC=local"

    # Ajouter l'utilisateur à chaque groupe correspondant à ses fonctions
    foreach ($fonction in $fonctions) {
        $groupName = $groupPrefix + $fonction
        $groupExists = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
        if ($groupExists) {
            Add-ADGroupMember -Identity $groupName -Members $username
        } else {
            # Créer le groupe s'il n'existe pas
            New-ADGroup -Name $groupName -GroupScope Global -Path $ouPath -Description "Groupe pour $fonction à $etablissement"
            Add-ADGroupMember -Identity $groupName -Members $username
        }
    }
}
