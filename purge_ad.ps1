# Importer les données du fichier CSV pour les établissements
$etablissements = Import-Csv -Path "etablissement.csv"

# Parcourir chaque établissement
foreach ($etablissement in $etablissements) {
    $ouName = $etablissement.Etablissements

    # Désactiver la protection contre la suppression pour l'unité d'organisation
    Set-ADOrganizationalUnit -Identity "OU=$ouName,DC=pourlesvieux,DC=local" -ProtectedFromAccidentalDeletion $false

    # Supprimer l'unité d'organisation
    Remove-ADOrganizationalUnit -Identity "OU=$ouName,DC=pourlesvieux,DC=local" -Recursive -Confirm:$false
}
