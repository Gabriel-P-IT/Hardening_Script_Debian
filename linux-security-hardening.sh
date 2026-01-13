#!/bin/bash

#############################################
# Script Ultra-Complet de Sécurisation Linux
# Version: 4.0
# Date: Janvier 2026
# Description: Automatise la sécurisation complète d'une VM Debian/Ubuntu
#############################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="/var/log/security-hardening"
BACKUP_DIR="/var/backups/security-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${SCRIPT_DIR}/security-hardening-$(date +%Y%m%d).log"

log() {
    echo -e "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error() {
    log "${RED}[ERROR]${NC} $1"
    exit 1
}

warning() {
    log "${YELLOW}[WARNING]${NC} $1"
}

success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

info() {
    log "${BLUE}[INFO]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root"
    fi
}

setup_directories() {
    info "Création backup directory avec permissions restrictives..."
    mkdir -p "$SCRIPT_DIR" "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    chmod 700 "$SCRIPT_DIR"
}

create_pre_hardening_snapshot() {
    info "=== CRÉATION SNAPSHOT PRÉ-SÉCURISATION ==="

    if ! command -v timeshift >/dev/null 2>&1; then
        warning "Timeshift non installé, aucun snapshot créé"
        return 1
    fi

    # Éviter les conteneurs
    if [[ -f /.dockerenv ]] || grep -qi docker /proc/1/cgroup 2>/dev/null; then
        warning "Environnement conteneur détecté, snapshot ignoré"
        return 1
    fi

    local snap_name="pre-hardening-$(date +%Y%m%d-%H%M%S)"
    info "Création du snapshot système: $snap_name"

    if timeshift --create --comments "Snapshot avant sécurisation Linux" --snapshot-tag "$snap_name"; then
        success "Snapshot créé: $snap_name"
        echo "Snapshot: $snap_name" > "$BACKUP_DIR/snapshot_info.txt"
        chmod 600 "$BACKUP_DIR/snapshot_info.txt"
    else
        warning "Échec de création du snapshot"
    fi
}

validate_password() {
    
    local uppercase=0
    local lowercase=0
    local digit=0
    local special=0
    
    [[ "$password" =~ [A-Z] ]] && uppercase=1
    [[ "$password" =~ [a-z] ]] && lowercase=1
    [[ "$password" =~ [0-9] ]] && digit=1
    [[ "$password" =~ [-_.@!\#%&*+=,;:?] ]] && special=1
    
    local entropy=$((uppercase + lowercase + digit + special))
    if [[ $entropy -lt 3 ]]; then  # Rejette si < 3 catégories
        return 1 
    fi
}

read_grub_password() {
    local pw1 pw2
    
    while true; do
        read -s -p "Mot de passe GRUB (min 12 chars): " pw1
        echo
        read -s -p "Confirmez le mot de passe: " pw2
        echo
        
        if [[ "$pw1" != "$pw2" ]]; then
            warning "Les mots de passe ne correspondent pas"
            continue
        fi
        
        if [[ -z "$pw1" ]]; then
            warning "Le mot de passe ne peut pas être vide"
            continue
        fi
        
        if ! validate_password "$pw1"; then
            warning "Le mot de passe doit contenir min 12 caractères et ne pas contenir: \$ \` \" ( ) { } ;"
            continue
        fi
        
        break
    done
    
    # Retourner le mot de passe validé
    echo "$pw1"
    pw1=""
    pw2=""
}

generate_grub_hash() {
    local password="$1"
    local hash
    
    # Génération du hash PBKDF2
    hash=$(printf '%s\n%s\n' "$password" "$password" | \
           grub-mkpasswd-pbkdf2 2>/dev/null) || \
        return 1
    
    # Extraction du hash uniquement
    hash=$(echo "$hash" | grep -oP '(?<=grub.pbkdf2=)\S+' | head -1)
    
    if [[ -z "$hash" ]]; then
        return 1
    fi
    
    echo "$hash"
}

backup_grub_hash() {
    local grub_user="$1"
    local grub_hash="$2"
    
    # Créer fichier contenant UNIQUEMENT le hash
    cat > "$BACKUP_DIR/grub_hash_only.txt" << EOF
# GRUB Hash Backup
# Generated: $(date)
# User: $grub_user
# DO NOT SHARE THIS FILE
GRUB_USER=$grub_user
GRUB_HASH=$grub_hash
EOF
    
    # Permissions restrictives
    chmod 600 "$BACKUP_DIR/grub_hash_only.txt"
    chown root:root "$BACKUP_DIR/grub_hash_only.txt"
}

backup_grub_with_gpg() {
    local grub_user="$1"
    local grub_password="$2"
    local grub_hash="$3"
    local temp_creds
    
    # Créer fichier temporaire sécurisé
    temp_creds=$(mktemp /tmp/grub_creds_XXXXXX) || return 1
    chmod 600 "$temp_creds"
    trap "shred -vfz -n 3 '$temp_creds' 2>/dev/null; rm -f '$temp_creds'" RETURN
    
    # Écrire les credentials dans le fichier temporaire
    cat > "$temp_creds" << EOF
GRUB_USER=$grub_user
GRUB_PASSWORD=$grub_password
GRUB_HASH=$grub_hash
EOF
    
    # Vérifier que GPG est installé
    if ! command -v gpg >/dev/null 2>&1; then
        warning "GPG non installé, fallback sur sauvegarde hash non-chiffré"
        backup_grub_hash "$grub_user" "$grub_hash"
        return 0
    fi
    
    # Chiffrement avec GPG (AES256)
    if ! gpg --symmetric --cipher-algo AES256 \
             --output "$BACKUP_DIR/grub_credentials.gpg" \
             "$temp_creds" 2>/dev/null; then
        warning "Chiffrement GPG échoué, fallback sur hash non-chiffré"
        backup_grub_hash "$grub_user" "$grub_hash"
        return 0
    fi
    
    # Permissions sur le fichier chiffré
    chmod 600 "$BACKUP_DIR/grub_credentials.gpg"
    chown root:root "$BACKUP_DIR/grub_credentials.gpg"
    
    # Détruire le fichier temporaire
    shred -vfz -n 3 "$temp_creds" 2>/dev/null || true
}

grub_hardening() {
    info "=== SÉCURISATION DE GRUB ==="
    
    # Vérifier GRUB disponible
    if [[ ! -f "/etc/grub.d/40_custom" ]]; then
        warning "/etc/grub.d/40_custom introuvable, GRUB non modifié"
        return 0
    fi
    
    # Lire nom d'utilisateur
    echo -n "Nom d'utilisateur GRUB [admin]: "
    read -r grub_user
    [[ -z "$grub_user" ]] && grub_user="admin"
    
    # Valider le username (alphanumérique + underscore)
    if ! [[ "$grub_user" =~ ^[a-zA-Z0-9_]+$ ]]; then
        error "Nom d'utilisateur invalide (alphanumérique + _ uniquement)"
    fi
    
    # Lire et valider le mot de passe
    grub_password=$(read_grub_password)
    
    # Générer le hash GRUB
    grub_hash=$(generate_grub_hash "$grub_password") || \
        error "Impossible de générer le hash GRUB"
    
    # Sauvegarder avec chiffrement GPG (avec fallback)
    backup_grub_with_gpg "$grub_user" "$grub_password" "$grub_hash"
    
    # Ajouter config GRUB
    cat >> /etc/grub.d/40_custom << EOF
# Configuration sécurisée GRUB
set superusers="$grub_user"
password_pbkdf2 $grub_user $grub_hash
set menu_color_normal=white/blue
set menu_color_highlight=black/light-gray
set timeout=5
EOF
    
    # Mettre à jour GRUB
    if command -v update-grub >/dev/null 2>&1; then
        update-grub || error "Erreur lors de la mise à jour GRUB"
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        grub2-mkconfig -o /boot/grub2/grub.cfg || error "Erreur lors de la mise à jour GRUB2"
    else
        error "Aucun gestionnaire GRUB trouvé"
    fi
    
    # Protéger les fichiers GRUB
    chmod 600 /boot/grub*/grub.cfg 2>/dev/null || true
    
    # Nettoyer les variables sensibles
    grub_password=""
    unset grub_password
    
    success "GRUB sécurisé avec utilisateur '$grub_user'"
    success "Backup sauvegardé dans $BACKUP_DIR"
}

create_secure_temp() {
    local template="$1"
    local tmpfile
    
    # Créer fichier temporaire sécurisé
    tmpfile=$(mktemp -t "$template") || return 1
    
    # Forcer permissions 600
    chmod 600 "$tmpfile"
    chown root:root "$tmpfile"
    
    echo "$tmpfile"
}

port_monitoring() {
    info "=== SURVEILLANCE DES PORTS OUVERTS ==="
    
    local port_baseline="/etc/security/allowed_ports.txt"
    local current_ports
    
    # Fichier temporaire sécurisé avec mktemp
    current_ports=$(create_secure_temp "ports_XXXXXX") || \
        error "Impossible de créer fichier temporaire"
    
    # Nettoyage automatique en cas d'erreur
    trap "rm -f '$current_ports'" RETURN
    
    # Récupérer les ports écoutants
    ss -tuln | grep LISTEN >> "$current_ports"
    
    # Créer baseline si elle n'existe pas
    if [[ ! -f "$port_baseline" ]]; then
        warning "Création de la baseline des ports autorisés..."
        mkdir -p /etc/security
        cp "$current_ports" "$port_baseline"
        chmod 600 "$port_baseline"
    else
        # Comparer avec baseline
        if ! diff -q "$port_baseline" "$current_ports" >/dev/null 2>&1; then
            warning "ALERTE: Déviation détectée par rapport à la baseline!"
            diff "$port_baseline" "$current_ports" | tee -a "$LOG_FILE" || true
        fi
    fi
    
    # Scan nmap optionnel (localhost uniquement)
    if command -v nmap >/dev/null 2>&1; then
        info "Scan nmap des ports localhost:"
        nmap -sT 127.0.0.1 2>/dev/null | grep "^[0-9]" | tee -a "$LOG_FILE" || true
    fi
}

special_bits_check() {
    info "=== VÉRIFICATION DES BITS SPÉCIAUX ==="
    
    local suid_baseline="/etc/security/suid_baseline.txt"
    local suid_current
    
    suid_current=$(create_secure_temp "suid_XXXXXX") || \
        error "Impossible de créer fichier temporaire"
    
    trap "rm -f '$suid_current'" RETURN
    
    info "Recherche des fichiers SUID..."
    find / \
      \( -path /proc -o -path /sys -o -path /run -o -path /snap -o -path /media -o -path /mnt \) -prune \
      -o -type f -perm -4000 -exec ls -l {} \; 2>/dev/null > "$suid_current"
    
    if [[ ! -f "$suid_baseline" ]]; then
        cp "$suid_current" "$suid_baseline"
        chmod 600 "$suid_baseline"
        chattr +i "$suid_baseline" 2>/dev/null || warning "Impossible de rendre baseline SUID immutable"
    else
        if ! diff -q "$suid_baseline" "$suid_current" >/dev/null 2>&1; then
            warning "ALERTE: Nouveaux fichiers SUID détectés!"
            diff "$suid_baseline" "$suid_current" | tee -a "$LOG_FILE" || true
        fi
    fi
    
    info "=== AUDIT DES FICHIERS SUID DÉTECTÉS ==="
    info "Les fichiers SUID trouvés sont listés ci-dessous."
    info "ATTENTION: La suppression du bit SUID peut casser des services!"
    info "Recommandation: Utiliser capabilities au lieu de SUID quand possible."
    info ""
    
    local suid_to_audit=(
        "/usr/bin/sudo"           
        "/usr/bin/passwd"
        "/usr/bin/chage"
        "/usr/bin/chfn"
        "/usr/bin/chsh"
        "/usr/bin/gpasswd"
        "/usr/bin/newgrp"
        "/sbin/unix_chkpwd"
    )
    
    info "Fichiers SUID critiques à AUDITER (ne pas supprimer):"
    for binary in "${suid_to_audit[@]}"; do
        if [[ -f "$binary" ]] && [[ -u "$binary" ]]; then
            ls -l "$binary" | tee -a "$LOG_FILE"
        fi
    done
    
    info ""
    info "Pour convertir SUID en capabilities (exemple):"
    info "  setcap cap_net_raw=ep /usr/bin/ping"
    info "  setcap cap_net_raw=ep /usr/bin/traceroute"
    info "  chmod u-s /usr/bin/ping  # SUPPRIMER SUID APRÈS capabilities"
    
    local dangerous_suid=(
        "/usr/bin/at"
        "/usr/bin/write"          
        "/usr/bin/wall"
        "/usr/lib/pt_chown"
    )
    
    info "=== SUPPRESSION SUID DANGEREUX ==="
    info "(Pause de 5s pour vérification manuelle)"
    sleep 5
    
    local suppressed=0
    for binary in "${dangerous_suid[@]}"; do
        if [[ -f "$binary" ]] && [[ -u "$binary" ]]; then
            chmod u-s "$binary"
            info "SUID supprimé de $binary"
            ((suppressed++))
        else
            info "$binary non trouvé ou sans SUID"
        fi
    done
    
    if [[ $suppressed -gt 0 ]]; then
        success "Supprimé $suppressed bits SUID dangereux"
    else
        info "Aucun SUID dangereux trouvé"
    fi
}


main() {
    check_root
    setup_directories

    create_pre_hardening_snapshot
    
    info "=== DÉBUT SÉCURISATION GRUB ==="
    grub_hardening
    
    info "=== VÉRIFICATION SÉCURITÉ SYSTÈME ==="
    port_monitoring
    special_bits_check
    
    success "Sécurisation terminée!"
}

main "$@"
