# Linux Security Hardening Script

Script Bash complet pour automatiser le durcissement de la sécurité sur systèmes Linux (Debian/Ubuntu principalement).  
Ce projet vise à regrouper en un seul outil l’ensemble des meilleures pratiques de sécurisation systèmes, avec génération de rapports, monitoring automatique et alertes email.

## État du projet

Ce script est en développement actif. Certaines parties restent à valider, tester ou améliorer (voir section *À faire*).

***

## Fonctionnalités principales

Le script exécute un enchaînement modulaire d’actions de sécurité couvrant tous les niveaux du système :

- Audit initial des utilisateurs, groupes et permissions  
- Désactivation des services inutiles et suppression des démons à risque (telnet, rsh, avahi, etc.)  
- Renforcement SSH : changement de port (par défaut 2222), restrictions, interdiction du root, etc.  
- Durcissement du sudoers (mot de passe obligatoire, logs détaillés, reset d’environnement)  
- Sécurisation du bootloader GRUB avec mot de passe administrateur  
- Installation et configuration automatique des outils suivants :  
  - Fail2ban  
  - ClamAV  
  - RKHunter  
  - CHKROOTKIT  
  - AIDE  
  - Lynis  
  - UFW  
  - Unhide, Logwatch, Auditd  
- Surveillance continue :  
  - Connexions et ports suspects  
  - Charge CPU / mémoire  
  - Connexions SSH multiples  
- Intégrité et alertes :  
  - Baseline d’empreintes SHA256 pour les fichiers critiques  
  - Comparaison automatique et notification email si divergence  
- Détection avancée de malware via combinaisons RKHunter / CHKROOTKIT / Unhide / fichiers récents  
- Mises à jour automatiques de sécurité  
- Rapports quotidiens et logs globaux  

***

## Structure modulaire

Chaque fonction du script représente un module indépendant :

| Module | Description |
|--------|--------------|
| `backupconfigs` | Sauvegarde de la configuration avant modifications |
| `usergroupaudit` | Audit utilisateurs et groupes |
| `sshhardening` | Sécurisation SSH |
| `sudoershardening` | Renforcement sudoers |
| `firewallsetup` | Configuration pare-feu UFW |
| `kernelhardening` | Paramètres sysctl renforcés |
| `integritychecker` | Vérification d’intégrité automatisée |
| `continuousmonitoring` | Surveillance en temps réel |
| `advancedmalwaredetection` | Scan malware et rootkits |
| `lynisintegration` | Audit complet avec Lynis |
| `finalreport` | Rapport et statistiques de fin de script |

***

## Installation

```bash
git clone https://github.com/Gabriel-P-IT/Hardening_Script_Debian.git
cd linux-security-hardening
chmod +x linux-security-hardening.sh
sudo ./linux-security-hardening.sh --email admin@domaine.com
```

### Options disponibles

| Option | Description |
|--------|--------------|
| `--dry-run` | Exécution à blanc (aucune modification système) |
| `--email EMAIL` | Adresse email d’envoi des alertes |
| `--skip-grub` | Ignore la sécurisation du GRUB |
| `--skip-ssh` | Ignore le durcissement SSH |
| `--help` | Affiche l’aide |
| `--version` | Affiche la version |

***

## Tâches automatisées

| Tâche | Fréquence |
|-------|------------|
| Scan anti-malware (RKHunter + CHKROOTKIT) | Quotidien à 3h |
| Vérification d’intégrité | Toutes les 4h |
| Rapport de sécurité | Quotidien à 6h |
| Surveillance connexions | Toutes les 15 min |
| Audit Lynis complet | Hebdomadaire (dimanche 2h) |

***

## Recommandations post-installation

1. Tester la connexion SSH via le nouveau port (2222 par défaut)  
2. Vérifier la réception des emails d’alerte  
3. Adapter les modules selon l’environnement d’exécution  
4. Configurer un serveur mail compatible (Postfix, ssmtp, etc.)  
5. Surveiller régulièrement les logs et rapports générés  
6. Créer une baseline d’intégrité après stabilisation du système  

***

## À faire

- [ ] Ajout d’une gestion d’erreurs plus robuste  
- [ ] Améliorer la compatibilité RHEL/CentOS  
- [ ] Gestion centralisée de la configuration via fichier `.conf`  
- [ ] Module SELinux/AppArmor  
- [ ] Vérification automatique de signatures de paquets  
- [ ] Support de containerisation (Docker/LXC)  
- [ ] Documentation technique détaillée pour chaque module  
- [ ] Intégration de visualisations via Grafana/ELK  
