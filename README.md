# MalyxScanner 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6.svg?logo=windows)](https://microsoft.com)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python)](https://python.org)
[![Vibe Coded](https://img.shields.io/badge/Vibe%20Coded-with%20Antigravity%20⚡-8A2BE2.svg)](https://deepmind.google)
[![Privacy: 100% Local](https://img.shields.io/badge/Privacy-100%25%20Local-success.svg)](#-confidentialité--vie-privée)

**MalyxScanner** est un analyseur de malwares et scanner statique **100% local, privé et open source** doté d'une interface graphique moderne typée SOC Cyber (*Dark Opaque*, *Midnight*, *OLED*, *Matrix*, *Light*).

---

## ✨ Fonctionnalités Principales

- 🛑 **Avis d'Exécution & Risques PC** : Décision claire (*Ne pas exécuter*, *Prudence*, *Autorisé*) avec l'explication précise des risques (vol de mots de passe, chiffrement ransomware, espionnage RAT, minage crypto).
- 🏷️ **Classification des Menaces** : Détection automatique des familles de malwares (Ransomware, Trojan/RAT, InfoStealer, Cryptominer, Dropper, Script malveillant, PE non signé).
- 📁 **Support Universel (12 Catégories)** : Analyse tous les fichiers sans restriction (Documents, Office, PDF/E-books, Images, Audio, Vidéos, Archives `.rar`/`.zip`/`.7z`, Exécutables `.exe`/`.dll`, Code source, Bases de données, Fichiers système, Assets de jeux vidéo).
- ⚡ **Moteur Anti-Freeze Haute Performance** : Traitement streaming ultra-rapide capable d'analyser des archives de plusieurs gigaoctets en quelques secondes sans bloquer l'interface.
- 🔬 **Analyse Statique Approfondie** :
  - Hachages unifiés : **MD5, SHA-1, SHA-256, SHA-512, CRC32, Imphash**.
  - **Structure PE** : Détection des signatures Authenticode, Debug PDB paths, Version Info (`StringFileInfo`), Sections W/X, Subsystem, APIs suspectes catégorisées MITRE ATT&CK.
  - **Entropie par Blocs** : Détection visuelle des zones packées, chiffrées ou compressées.
  - **Extracteur d'IOCs** : Extraction des URLs, adresses IP, commandes sensibles (`powershell`, `vssadmin`, `certutil`), clés de registre et mots-clés de rançon.
  - **Signatures YARA** : Règles intégrées et dossier `rules/` extensible pour vos propres signatures.
- 🌐 **VirusTotal (Optionnel / Recommandé)** : Interrogation de réputation sur 70+ antivirus via empreinte SHA-256 uniquement (*aucun fichier n'est téléversé*).
- 🎨 **5 Thèmes Visuels & Profils de RAM** : Choix entre *Cyber Dark*, *Midnight Blue*, *OLED Black*, *Matrix Emerald*, *Light Mode*, et profils de mémoire (*Économie de RAM*, *Équilibré*, *Vitesse Maximale*).
- 📄 **Exportation de Rapports** : Sauvegarde des analyses au format **TXT** et **JSON**.
- 🌍 **Bilingue** : Interface 100% traduite en **Français** et **Anglais**.

---

## 🔒 Confidentialité & Vie Privée

| Donnée | Traitement | Destination |
| :--- | :--- | :--- |
| **Contenu de vos fichiers** | Traité 100% en local | **Nulle part (jamais téléversé)** |
| **Empreinte SHA-256** | Uniquement si l'option VirusTotal est activée | VirusTotal (API) |
| **Télémétrie & Logs** | Aucune collecte | **100% Privé** |

---

## 🚀 Installation & Lancement Rapide

### Prérequis
- Windows 10 / 11 (64-bit)
- Python 3.11+

### Cloner et lancer
```powershell
git clone https://github.com/maelmeriguet4-glitch/MalyxScanner.git
cd MalyxScanner
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python src/main.py
```

> **Note YARA (Optionnel)** : Le moteur YARA s'installe automatiquement sur Python 3.11 (`yara-python`). Sur Python 3.12+, si Visual C++ n'est pas installé sur votre machine, MalyxScanner démarre et fonctionne parfaitement avec tous ses autres moteurs d'analyse heuristique.

### Lancer les tests unitaires
```powershell
.venv\Scripts\python.exe tests/test_analyzer.py
```

---

## 📦 Compiler l'Exécutable Portable (.exe)

Pour générer l'exécutable autonome pour Windows :

```powershell
.venv\Scripts\pyinstaller.exe --noconfirm MalyxScanner.spec
```

L'exécutable standalone sera généré dans `dist\MalyxScanner\MalyxScanner.exe`.

---

## 📬 Contact, Suggestions & Bugs

Une idée d'amélioration, une recommandation ou un bug à signaler ?
- **Développeur** : Mael Meriguet
- **E-mail** : [maelmeriguet4@proton.me](mailto:maelmeriguet4@proton.me?subject=[MalyxScanner]%20Feedback%20/%20Rapport%20de%20Bug)

---

## 📜 Licence

Ce projet est sous licence open source **MIT** — voir le fichier [LICENSE](LICENSE) pour plus de détails.
