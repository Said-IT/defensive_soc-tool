# Defensive SOC Tool

Ce projet est un outil défensif automatisé conçu pour vérifier la sécurité d'un hash de fichier, d'une adresse e-mail et d'une adresse IP en utilisant des API publiques telles que VirusTotal, EmailRep et AbuseIPDB. L'outil génère également un rapport détaillé des résultats des vérifications.

## Fonctionnalités

- **Vérification de hash** : Utilise l'API de VirusTotal pour déterminer si le hash est malveillant.
- **Analyse d'e-mail** : Utilise l'API EmailRep pour fournir des informations sur l'adresse e-mail, y compris les indicateurs de compromission.
- **Analyse d'IP** : Utilise l'API AbuseIPDB pour obtenir des informations sur l'adresse IP, y compris son statut de réputation.
- **Génération de rapport** : Crée un rapport automatisé avec tous les résultats des vérifications.

## Prérequis

- Python 3.x
- Bibliothèques Python : `requests`

Vous pouvez installer les dépendances requises à l'aide de `pip` :

```bash
pip install requests 
```
Configuration des API
Avant d'exécuter l'outil, remplacez les clés API suivantes dans le script :

```bash
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
EMAILREP_API_KEY = 'YOUR_EMAILREP_API_KEY'
ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_API_KEY'
```

Obtenez vos clés API en vous inscrivant sur les sites suivants :

=>VirusTotal
=>EmailRep
=>AbuseIPDB


##Utilisation

Pour exécuter l'outil, utilisez la commande suivante dans votre terminal :
```bash
python defensive_tool.py <hash> <email> <ip>
```


##Contributions

Les contributions sont les bienvenues ! Veuillez soumettre un pull request ou ouvrir une issue pour discuter des améliorations.

