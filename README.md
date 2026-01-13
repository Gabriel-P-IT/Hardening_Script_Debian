# Linux Security Hardening Script v4.0

Script Bash pour automatiser le durcissement de la sécurité sur systèmes Linux Debian/Ubuntu.

**Destiné à être exécuté au premier lancement de la VM** (dès après l'installation initiale du système d'exploitation, avant tout déploiement en production).

Ce script se concentre sur **trois fonctionnalités principales** : sécurisation du bootloader GRUB, monitoring des ports ouverts, et audit des fichiers SUID.

---

## ⚠️ État du Projet

**Stade de développement : Prototype fonctionnel (non production-ready)**

Ce script contient des **défauts de sécurité** qui le rendent dangereux en environnement de production.

---

## 🚀 Cas d'Usage Principal

### ✅ Approprié pour

- **Sécurisation initiale de VM** fraîchement installées
- Environnements **lab/apprentissage/CTF**
- **Tests locaux** sur VM isolée avant déploiement
- Base pour développer un vrai script de hardening production-grade
- Étude des bonnes pratiques bash et sécurité Linux

### ❌ NON approprié pour

- Production (défauts de sécurité)
- Systèmes critiques ou en service
- Environnements cloud/containerisés (Docker, Kubernetes)
- Compliance réglementaire (GDPR, ISO27001, etc.)
- VMs déjà configurées/en exploitation

---

## Fonctionnalités Implémentées

### 1. Sécurisation du Bootloader GRUB
- Génération de hash PBKDF2 pour le mot de passe GRUB
- Validation password améliorée (12+ chars, 3+ catégories: maj/min/chiffres/spéciaux)
- Chiffrement des credentials avec GPG (AES256) + fallback hash simple
- Sauvegarde sécurisée des backups (permissions 600)
- Protection des fichiers GRUB (chmod 600)
- Support GRUB1 (`update-grub`) et GRUB2 (`grub2-mkconfig`)
- Snapshot système optionnel (détection conteneur intégrée)

### 2. Surveillance des Ports
- Capture de l'état des ports écoutants (`ss`)
- Création d'une baseline de ports autorisés
- Détection de déviation par rapport à la baseline
- Protections baseline : permissions 600 + immutable flag

### 3. Audit des Fichiers SUID
- Scan récursif des fichiers SUID
- Exclusion des répertoires virtuels (`/proc`, `/sys`, `/run`, etc.)
- Création d'une baseline SUID avec protection immutable
- Alerte sur détection de nouveaux SUID
- Audit des fichiers SUID critiques (sudo, passwd, chage, gpasswd, etc.)
- Recommandations pour utiliser capabilities au lieu de SUID

### 4. Infrastructure Générale
- Logs structurés avec timestamps dans `/var/log/security-hardening`
- Gestion de snapshots Timeshift (optionnel, détection conteneur)
- Gestion des répertoires backup sécurisés (permissions 700)
- Vérification root obligatoire
- Gestion colorisée des messages (INFO, WARNING, ERROR, SUCCESS)

---

## Installation & Déploiement Initial

### Prérequis

```bash
# Système d'exploitation fraîchement installé (Debian 11+ ou Ubuntu 20.04+)
# Accès root ou sudo
# Environ 5-10 minutes pour l'exécution complète
```

### Étapes de Déploiement

```bash
# 1. Télécharger le script
wget https://exemple.com/linux-security-hardening-v4.1.sh
chmod +x linux-security-hardening-v4.1.sh

# 2. Vérifier le contenu du script avant exécution
less linux-security-hardening-v4.1.sh

# 3. Exécuter immédiatement après installation du système
sudo ./linux-security-hardening-v4.1.sh

# 4. Le script exécute automatiquement :
#    - Snapshot pré-sécurisation (si Timeshift installé)
#    - Demande d'interaction (password GRUB + username)
#    - Sécurisation GRUB
#    - Monitoring des ports
#    - Audit SUID
#    - Génération des logs
```

### Dépendances

| Outil | Statut | Utilisé pour |
|-------|--------|--------------|
| `bash` 4.0+ | **Requis** | Exécution script |
| `grub-mkpasswd-pbkdf2` | **Requis** | Hash GRUB |
| `gpg` | **Optionnel** | Chiffrement credentials |
| `timeshift` | **Optionnel** | Snapshots système |
| `ss` ou `netstat` | **Requis** | Port monitoring |
| `nmap` | **Optionnel** | Scan ports avancé |

```bash
# Installer les dépendances manquantes (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y grub2 gpg timeshift net-tools
```

---

## Mode d'Utilisation

### Exécution Standard

```bash
sudo ./linux-security-hardening-v4.1.sh
```

Le script affichera des prompts interactifs :

```
=== CRÉATION SNAPSHOT PRÉ-SÉCURISATION ===
[INFO] Création du snapshot système: pre-hardening-20260113-103600
[SUCCESS] Snapshot créé: pre-hardening-20260113-103600

=== DÉBUT SÉCURISATION GRUB ===
Nom d'utilisateur GRUB [admin]: admin
Mot de passe GRUB (min 12 chars, majuscules, minuscules, chiffres): ••••••••••••••
Confirmez le mot de passe: ••••••••••••••

[SUCCESS] GRUB sécurisé avec utilisateur 'admin'
[SUCCESS] Backup sauvegardé dans /var/backups/security-20260113-103600/

=== VÉRIFICATION SÉCURITÉ SYSTÈME ===
[INFO] Création de la baseline des ports autorisés...
[INFO] Recherche des fichiers SUID...
[INFO] Fichiers SUID critiques à AUDITER (ne pas supprimer)...

[SUCCESS] Sécurisation terminée!
```

### Validations Requises

Le script demandera :

1. **Mot de passe GRUB**
   - Minimum 12 caractères
   - Au moins 3 catégories : majuscules, minuscules, chiffres, caractères spéciaux
   - Caractères autorisés : `[-_.@!#%&*+=,;:?]`
   - Caractères interdits : `$ ` " { } ( ) ; \ | & < >`
   - Confirmé deux fois

2. **Nom utilisateur GRUB** (défaut: `admin`)
   - Format : alphanumérique + underscore uniquement

---

## Structure des Fichiers Générés

```
/var/log/security-hardening/
├── security-hardening-YYYYMMDD.log        # Logs quotidiens structurés

/var/backups/security-YYYYMMDD-HHMMSS/
├── snapshot_info.txt                      # Info snapshot Timeshift
├── grub_hash_only.txt                     # Hash GRUB (fallback, plaintext)
├── grub_credentials.gpg                   # Credentials GRUB chiffrés (GPG)
└── [autres fichiers de sauvegarde]

/etc/security/
├── allowed_ports.txt                      # Baseline des ports autorisés (immutable)
└── suid_baseline.txt                      # Baseline des fichiers SUID (immutable)
```

### Permissions de Sécurité

| Fichier | Permissions | Propriétaire | Justification |
|---------|-------------|--------------|---------------|
| `/var/backups/security-*/` | `700` | root:root | Accès root uniquement |
| `grub_credentials.gpg` | `600` | root:root | Chiffré, root seul |
| `grub_hash_only.txt` | `600` | root:root | Hash plaintext, root seul |
| `/etc/security/allowed_ports.txt` | `600` | root:root | Baseline ports (immutable) |
| `/etc/security/suid_baseline.txt` | `600` | root:root | Baseline SUID (immutable) |
| `/var/log/security-hardening/` | `750` | root:root | Logs lisibles root |

---

## ❌ Limitations

### Nettoyage Mémoire Insuffisant
```bash
grub_password=""
unset grub_password
```
Cette approche ne purge pas la RAM. Le password reste potentiellement accessible via `/proc/[pid]/mem`, core dumps, ou outils forensic.

### Credentials en Fichier Temporaire
Même avec `shred`, les blocs disque restent récupérables via forensics avant chiffrement GPG. Les SSDs ne garantissent pas le TRIM.

### Baseline Non-Auditée
Les fichiers baseline peuvent être modifiés par root sans trace. Manque : signatures GPG, versioning git, intégration auditd.

### Validation Password
La validation n'inclut pas d'analyse d'entropie réelle (zxcvbn) ni de rejet des dictionnaires de mots courants.

### Scan SUID Coûteux
Le scan complet du filesystem peut prendre 5-30 minutes sur de gros systèmes et générer du bruit I/O.

### Pas d'Options CLI
Le script ne supporte aucune option (`--dry-run`, `--skip-grub`, `--help`, etc.). Il exécute toujours l'intégralité des actions.

---

## Logs et Diagnostics

### Localisation des Logs

```bash
# Logs quotidiens
/var/log/security-hardening/security-hardening-YYYYMMDD.log

# Sauvegardes/Backups
/var/backups/security-YYYYMMDD-HHMMSS/
```

### Consultation des Logs

```bash
# Afficher tous les logs en temps réel
tail -f /var/log/security-hardening/security-hardening-*.log

# Rechercher les erreurs
grep ERROR /var/log/security-hardening/security-hardening-*.log

# Chercher les avertissements
grep WARNING /var/log/security-hardening/security-hardening-*.log

# Audit de la sécurisation GRUB
grep "GRUB sécurisé" /var/log/security-hardening/security-hardening-*.log

# Alertes de déviation baseline
grep "ALERTE" /var/log/security-hardening/security-hardening-*.log
```

---

## Sécurité des Sauvegardes & Credentials

### Credentials GRUB Stockés

Les credentials GRUB sont sauvegardés de deux manières (avec fallback) :

**Option 1 : Chiffré GPG (préféré)**
```
/var/backups/security-.../grub_credentials.gpg
```
- Algorithme : AES256 (symétrique)
- Déchiffrement : `gpg --decrypt grub_credentials.gpg`
- Permissions : `600` (root seul)

**Option 2 : Hash seul (fallback si GPG indisponible)**
```
/var/backups/security-.../grub_hash_only.txt
```
- Contient : Hash PBKDF2 + username
- Permissions : `600` (root seul)
- **ATTENTION** : Hash seul, pas le plaintext password

### Protections Appliquées

| Élément | Protection |
|---------|-----------|
| Backup directory | `chmod 700` (root seul) |
| Credentials GPG | `chmod 600` + chown root |
| Hash backup | `chmod 600` + chown root |
| GRUB config | `chmod 600` |
| Logs parent dir | `chmod 750` |

### Récupération des Credentials

En cas de perte :

```bash
# Si GPG disponible
gpg --decrypt /var/backups/security-20260113-103600/grub_credentials.gpg

# Si GPG non disponible (fallback)
cat /var/backups/security-20260113-103600/grub_hash_only.txt
```

---

## Compatibilité

| Système | Statut | Notes |
|---------|--------|-------|
| Debian 10 (Buster) | ✅ | Recommandé |
| Debian 11 (Bullseye) | ✅  | Basé sur Debian |
| Debian 12 (Bookworm) | ✅  | GRUB compatible |
| Ubuntu 18.04 LTS | ✅  | Basé sur Debian |
| Ubuntu 20.04 LTS | ✅  | Basé sur Debian |
| Ubuntu 22.04 LTS | ✅  | Basé sur Debian |

---

## Workflow d'Utilisation Recommandé

### Phase 1 : Préparation (5 min)

```bash
# 1. Installer OS minimal (Debian 11)
# → Ne installer QUE base system + openssh-server

# 2. Télécharger script
wget https://repo.example.com/linux-security-hardening-v4.1.sh
chmod +x linux-security-hardening-v4.1.sh
```

### Phase 2 : Exécution (10 min)

```bash
# 3. Créer snapshot pré-sécurisation (optionnel mais recommandé)
sudo timeshift --create --comments "Before hardening"

# 4. Lancer le script en root
sudo ./linux-security-hardening-v4.1.sh
```

### Phase 3 : Vérification (5 min)

```bash
# 5. Vérifier les logs
tail -50 /var/log/security-hardening/security-hardening-*.log

# 6. Vérifier GRUB sécurisé
ls -la /boot/grub*/grub.cfg
# Doit montrer: chmod 600

# 7. Vérifier snapshots
sudo timeshift --list

# 8. Vérifier backups créés
ls -la /var/backups/security-*/
```

### Phase 4 : Hardening Supplémentaire (30 min+)

Après le script v4.1, appliquer manuellement :

```bash
# SSH hardening (port 2222, root interdit, etc.)
sudo nano /etc/ssh/sshd_config

# Firewall UFW
sudo ufw default deny incoming
sudo ufw allow 22/tcp  # Adapter port SSH
sudo ufw enable

# Fail2ban
sudo apt-get install -y fail2ban
sudo systemctl enable fail2ban

# ClamAV (anti-malware)
sudo apt-get install -y clamav clamav-daemon

# AIDE (file integrity)
sudo apt-get install -y aide aide-common
sudo aideinit

# Auditd (kernel logging)
sudo apt-get install -y auditd
sudo systemctl enable auditd
```

---

## Licence & Avertissement ⚠️

**AVERTISSEMENT CRITIQUE** : Ce script modifie la configuration système de manière **permanente et potentiellement destructrice**.

Son utilisation est **à vos risques et périls**.

### Recommandations Obligatoires

- ✅ Tester **TOUJOURS** sur **VM isolée** d'abord (pas réseau)
- ✅ **Créer snapshot** avant exécution (Timeshift recommandé)
- ✅ **Lire intégralement** le script avant exécution
- ✅ **Vérifier TOUS les logs** après exécution
- ✅ **Créer point de restore** (snapshot, backup disque)
- ✅ **Ne pas utiliser en production** sans thorough testing
- ✅ Vérifier les fonctionnalités GRUB après reboot

### Liability

Je n'assume **aucune responsabilité** pour :
- Perte de données
- Indisponibilité système
- Corruption bootloader
- Fuites de credentials
- Tous dégâts directs ou indirects

**Utilisez à vos propres risques.**

---

## Roadmap v5.0

### 🔴 Critiques (doit-avoir)
- [ ] Implémenter `--dry-run` mode
- [ ] Ajouter `--skip-GRUB`, `--skip-snapshot` options
- [ ] Sécuriser memory cleanup (chiffrement en RAM)

### Importants
- [ ] Support IPv6 dans port monitoring
- [ ] Intégration auditd minimal
- [ ] Configuration depuis fichier `.conf`

### Later
- [ ] Support RHEL/CentOS
- [ ] Monitoring continu (systemd timer)
- [ ] Integration Sysctl hardening (kernel params)
- [ ] SELinux/AppArmor profiles
- [ ] Tests automatisés (shellcheck, bats)

---

## Références & Ressources

### Sécurité Linux
- [CIS Benchmark - Debian Linux](https://www.cisecurity.org/benchmark/debian_linux/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Linux Security Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)

### Référence Bash
- [GNU Bash Manual](https://www.gnu.org/software/bash/manual/)
- [ShellCheck - Static Analysis for Bash](https://www.shellcheck.net/)
- [Defensive BASH Programming](http://www.kfirlavi.com/blog/2012/11/14/defensive-bash-programming/)

### Documentation Système
- [GRUB2 Manual](https://www.gnu.org/software/grub/manual/grub.html)
- [Debian Security Wiki](https://wiki.debian.org/Security)
- [Linux Kernel Documentation](https://www.kernel.org/doc/)

### Outils Complémentaires
- [Lynis - Security Auditing Tool](https://github.com/CISOfy/lynis)
- [AIDE - File Integrity Tool](https://aide.github.io/)
- [auditd - Kernel Audit Framework](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [Timeshift - System Restore](https://github.com/teejee2008/timeshift)

---


*Last Updated: Janvier 2026 - v4.0*
