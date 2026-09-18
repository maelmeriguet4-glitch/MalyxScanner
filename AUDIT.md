# Audit de MalyxScanner

## Résumé exécutif

Note globale : 7,3/10

Verdict : projet ambitieux et utile, avec une base solide, mais encore inachevé sur la maturité logicielle : tests incomplets, dépendances peu figées et quelques incohérences entre la logique de classification de fichiers et les règles de menace.

### 3 points forts majeurs

1. Proposition de valeur claire et fonctionnelle : le projet a un objectif précis, un comportement de scan statique de fichiers local, et un système de risque/avis d'exécution assez bien pensé (`README.md`, `src/core/analyzer.py`, `src/core/threat_classifier.py`).
2. Couverture de tests locale réaliste : la suite `tests/test_analyzer.py` couvre des cas utiles (hashes, fichiers texte, PE factices, entropy, rapports exportés, thèmes, familles de fichiers). Le lancement local est fonctionnel.
3. Respect de la confidentialité et UX orientée SOC : le projet insiste sur un traitement 100 % local et propose une interface visuelle avec plusieurs thèmes et export de rapports (`README.md`, `src/gui/app.py`).

### 3 problèmes majeurs

1. Quelques tests sont des stubs sans assertion : des méthodes telles que `test_strings_extraction_ioc` et `test_threat_classification_ransomware` ne vérifient rien, ce qui réduit la valeur de la suite (`tests/test_analyzer.py`).
2. La gestion de dépendances est fragile : `requirements.txt` utilise des plages de versions non figées, sans fichier de lock ni pipeline CI, ce qui rend la reproductibilité faible (`requirements.txt`, absence de `.github/workflows`).
3. Incohérence dans la logique de détection : `threat_classifier.py` teste `family == "script"`, mais `filetype.py` ne définit aucun type `script` ; la classification de script est donc partiellement morte ou incohérente (`src/core/filetype.py`, `src/core/threat_classifier.py`).

---

## Présentation du projet

MalyxScanner est un scanner statique de malwares pour Windows, orienté "100 % local, privé et open source". Il vise à analyser les fichiers, calculer les hashes, repérer les IOCs, classifier les familles, estimer le risque, et proposer un avis d'exécution basé sur des indicateurs heuristiques.

Stack observé :
- Langage : Python 3.11+
- Interface : customtkinter
- Analyse PE : pefile
- Détection de type : puremagic
- Signatures : yara-python
- Dépendances HTTP : requests

Taille approximative :
- Environ 20 fichiers Python sources + tests + règles YARA
- Projet de taille intermédiaire, encore jeune mais déjà bien orienté produit
- Historique Git très court : 2 commits visibles, ce qui est un signe de maturité limitée et de faible industrialisation

---

## Tableau des notes par critère

Pondération par défaut appliquée : Critères `code`, `tests` et `securite` sont multipliés par 2 ; les autres par 1.

| Critère | Note | Coefficient | Commentaire |
|---|---:|---:|---|
| Architecture et structure | 7,5 | 1 | Structure claire et cohérente dans `src/core` et `src/gui` |
| Qualité du code | 7,0 | 2 | Bonnes fonctions isolées, mais quelques incohérences de logique et dupliquations de règles |
| Tests et fiabilité | 7,5 | 2 | Suite utile, mais plusieurs tests sont vacants ou incomplets |
| Sécurité | 7,5 | 2 | Local-only et absence de téléversement, mais pas de revues de sécurité formelles ni d'audit dépendances |
| Documentation | 8,0 | 1 | README solide et orienté usage, mais pas de guide de contribution ni de CI |
| Dépendances et build | 6,0 | 1 | Dépendances peu verrouillées; pas de CI ni de pipeline de validation |
| Performance et scalabilité | 8,0 | 1 | Analyse streaming, limites de taille, bon sens performance |
| Maintenabilité et hygiène Git | 6,5 | 1 | Repo propre, mais historique court et peu de maturité pipeline/branches |

Calcul :

(7,5×1 + 7,0×2 + 7,5×2 + 7,5×2 + 8,0×1 + 6,0×1 + 8,0×1 + 6,5×1) / 11 = 80,5 / 11 = 7,3

Note globale : 7,3/10

---

## Analyse détaillée par critère

### 1) Architecture et structure

Ce qui va :
- La séparation est globalement lisible entre `src/core` (analyse, scoring, extraction, PE, YARA) et `src/gui` (interface) (`src/core/analyzer.py`, `src/gui/app.py`).
- Les fichiers portent des responsabilités cohérentes, notamment `filetype.py`, `pe_analysis.py`, `risk_score.py`, `strings_extractor.py`.

Ce qui ne va pas :
- Certaines responsabilités sont assez mélangées dans `analyzer.py` : la fonction `analyze_file()` orchestre beaucoup d'étapes de détection, ce qui la rend un point de friction pour les tests et l'évolution.
- Le projet se comporte comme un produit unique plutôt qu'un paquet de modules réutilisables ; il gagnerait à avoir des frontières plus explicites entre "décision d'analyse", "classification", "exposition UI" et "export de rapport".

Preuves : `src/core/analyzer.py`, `src/gui/app.py`.

### 2) Qualité du code

Ce qui va :
- Les fonctions ont des noms explicites et le code est généralement lisible.
- Les modules de calcul de risque, d'entropie et d'extraction de chaînes sont de bonne taille et sans surcharge brutale.

Ce qui ne va pas :
- `threat_classifier.py` contient des conditions qui ne correspondent pas à la réalité des familles produites par `filetype.py` : le test `family == "script"` est un symptôme d'un modèle plus ancien ou incomplet (`src/core/threat_classifier.py`).
- Comme dans beaucoup de projets single-maintainer, certains points de logique sont répétés et moins centralisés qu'ils ne devraient l'être.

Preuves : `src/core/filetype.py` et `src/core/threat_classifier.py`.

### 3) Tests et fiabilité

Ce qui va :
- Il existe une suite de tests utile, qui couvre des aspects de base de l'analyse et des exports (`tests/test_analyzer.py`).
- Le projet exécute bien localement : `python -m unittest tests.test_analyzer -q` est vert dans cet environnement après installation des dépendances.

Ce qui ne va pas :
- Les tests `test_strings_extraction_ioc` et `test_threat_classification_ransomware` sont inachevés : ils n'ont ni assertion ni `assert` explicite, donc ils ne valident rien (`tests/test_analyzer.py`).
- Il manque des tests sur les cas limites de dépendances manquantes, de fichiers récursifs, de permissions, et de grandes archives.

Preuves : `tests/test_analyzer.py`.

### 4) Sécurité

Ce qui va :
- Le produit est explicitement local-only et ne téléverse pas le fichier, à l'exception de l'option VirusTotal qui ne touche qu'un hash SHA-256 (`README.md`, `src/core/analyzer.py`).
- Cette posture est cohérente avec un outil de sécurité/statique destiné à l'analyse de suspects.

Ce qui ne va pas :
- Le dépôt ne contient pas de revue de sécurité formelle ni de politique de dépendances sécurisées.
- `virustotal.py` dépend d'un appel réseau direct avec gestion basique d'erreurs, mais il n'y a ni configuration de timeout robuste ni aucun mécanisme de cache ou de sécurité autour des clés API.

Preuves : `src/core/virustotal.py`, `README.md`.

### 5) Documentation

Ce qui va :
- README clair, orienté usage, avec installation et compilation `.exe` détaillées (`README.md`).
- Les fonctionnalités sont décrites de façon accessible pour un utilisateur technique ou SOC.

Ce qui ne va pas :
- Il n'y a pas de guide détaillé de contribution, pas de note sur le modèle de données internes, ni d'explication sur l'architecture pour les contributeurs futurs.
- Le dépôt ne documente pas clairement les règles YARA ou la stratégie de scoring ; ces éléments sont importants pour le maintien à long terme.

Preuves : `README.md`, `rules/`.

### 6) Dépendances et build

Ce qui va :
- Le dépôt dispose d'un `requirements.txt` lisible et d'un chemin d'installation simple.
- Le projet est exécutable en local avec Python.

Ce qui ne va pas :
- Les dépendances sont des plages (`>=`) et non des versions figées, ce qui rend les builds moins reproductibles.
- Il n'y a ni `pyproject.toml`, ni `poetry.lock`, ni `requirements-dev.txt`, ni pipeline CI pour exécuter automatiquement les tests à chaque commit.
- L'absence de workflow GitHub est visible par l'absence de dossier `.github/workflows`.

Preuves : `requirements.txt`, absence de configuration CI dans le dépôt.

### 7) Performance et scalabilité

Ce qui va :
- Les fichiers de scanner utilisent des limites strictes (ex. `MAX_SCAN_BYTES = 2 * 1024 * 1024` dans `strings_extractor.py`) pour éviter de bloquer l'interface.
- Les analyses PE et le scoring sont segmentés en modules précis et restent lisibles.

Ce qui ne va pas :
- L'architecture de scan est bien pensée pour le local, mais elle ne protège pas encore assez contre les fichiers de taille extrême ou les formats non standard qui peuvent nécessiter davantage de validation en production.
- La performance a été pensée pour un usage individuel et non pour un traitement massif ou parallèle.

Preuves : `src/core/strings_extractor.py`, `src/core/analyzer.py`.

### 8) Maintenabilité et hygiène Git

Ce qui va :
- Le dépôt est propre, il y a une licence MIT, les fichiers sont organisés et le README est sérieux.
- Les modifications semblent concentrées sur un même axe fonctionnel.

Ce qui ne va pas :
- Le historique Git est très court ; le projet n'a pas encore la maturité d'un dépôt avec plusieurs cycles de maintenance, revue et releases.
- Il manque de conventions de qualité de contribution (lint, format, CI, templates d'issue/PR).

Preuves : `git log` local, présence de `LICENSE`, absence de `.github`.

---

## Plan d'action

### 1. Urgent (à faire tout de suite)

1. Corriger les tests vides et rendre la suite fiable
   - Où : `tests/test_analyzer.py`
   - Pourquoi : un test qui ne vérifie rien donne un faux sentiment de sécurité
   - Effort : Faible
   - Impact : Fort

2. Harmoniser les familles détectées et la logique de menace
   - Où : `src/core/filetype.py`, `src/core/threat_classifier.py`
   - Pourquoi : la détection de script et autres classifications sont incohérentes, ce qui nuit à l'annonce de résultats précis
   - Effort : Faible à Moyen
   - Impact : Fort

3. Ajouter une base CI minimale
   - Où : dossier `.github/workflows` (à créer)
   - Pourquoi : exécuter automatiquement les tests sur chaque push/PR améliore la fiabilité du projet
   - Effort : Moyen
   - Impact : Fort

### 2. Important (court terme)

1. Verrouiller les dépendances de build
   - Où : `requirements.txt`, éventuellement `pyproject.toml`
   - Pourquoi : stabilité des builds et reproductibilité pour les utilisateurs et contributeurs
   - Effort : Faible
   - Impact : Moyen

2. Ajouter des tests sur les cas limites 
   - Où : `tests/test_analyzer.py`
   - Pourquoi : sécuriser les cas de fichiers non standards, permissions, archives et PE fortement trompeurs
   - Effort : Moyen
   - Impact : Fort

3. Documenter le modèle de scoring et le format des résultats de scan
   - Où : `README.md` et documents du dépôt
   - Pourquoi : faciliter la maintenance et l'intégration de nouveaux détecteurs
   - Effort : Moyen
   - Impact : Moyen

### 3. Amélioration (moyen terme)

1. Séparer les responsabilités entre orchestration, heuristiques et UI
   - Où : `src/core/analyzer.py`, `src/gui/app.py`
   - Pourquoi : gagne en testabilité et maintenabilité
   - Effort : Moyen
   - Impact : Moyen

2. Introduire un système de règles plus explicite et centralisé
   - Où : `src/core/*`
   - Pourquoi : réduire la duplication et rendre la logique de détection plus facile à auditer
   - Effort : Moyen à Élevé
   - Impact : Moyen

3. Rendre le projet plus "open source mature"
   - Où : .github/, docs/ et templates
   - Pourquoi : améliorer l'entrée du contributeur et la qualité globale du dépôt
   - Effort : Moyen
   - Impact : Moyen

Estimation du gain de note si le plan 1 + 2 est appliqué : de 7,3/10 vers environ 8,2-8,7/10, surtout grâce à la fiabilité, la reproductibilité et les validations automatiques.

---

## Limites de l'analyse

- L'analyse a été faite sur le code source et sur la suite de tests locale, sans exécution du binaire Windows compilé.
- Je n'ai pas validé les dépendances externes via un scanner de vulnérabilités spécifique (par exemple SCA/advisory) ; c'est une limite de l'environnement et de l'absence de pipeline.
- Le projet est orienté sécurité et heuristique ; la qualité de la détection ne se juge pas uniquement par le code source, mais par son usage réel sur des échantillons de malware et des cas réels.

---

## Conclusion

MalyxScanner a une vraie base solide pour un outil local de détection statique, avec une valeur claire et une interface soignée. Ce qui manque aujourd'hui n'est pas une vision, mais une maturité logicielle : tests robustes, CI, dépendances figées et cohérence logique dans la détection. Le projet est déjà bon pour un prototype/prod interne, mais il mérite encore un cycle de hardening avant d'être traité comme un outil de confiance partagé à grande échelle.
