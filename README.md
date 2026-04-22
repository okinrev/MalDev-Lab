# MalDev-Lab

Générateur de loader Nim pour la recherche en développement offensif. Une interface web permet de configurer un shellcode et ses options ; le serveur produit une source Nim (`loader.nim`) prête à être compilée, packagée dans une archive ZIP.

> Projet à usage strictement pédagogique et de recherche (labs, CTF, red team authorisé). Ne pas utiliser sur des systèmes sans autorisation explicite.

## Fonctionnalités

- Chiffrement XOR du shellcode avec clé aléatoire
- Obfuscation XOR des chaînes sensibles (noms de DLL et d'API NT)
- Choix entre injection **locale** ou **distante** (process ciblé configurable)
- Sortie **EXE** ou **DLL**
- Plusieurs techniques d'exécution (A/B/C/D)
- Personnalisation des noms de fonctions générées

## Structure

```
.
├── src/
│   ├── back.py             # serveur Flask (API + UI)
│   ├── index.html          # interface web
│   └── templates/
│       └── loader.nim      # template Jinja du loader Nim
├── shellcode.txt           # shellcode d'exemple (calc.exe)
└── utilisation.txt
```

## Prérequis

- Python 3.9+
- Flask
- Nim (pour compiler le loader généré)

```bash
pip install flask
```

## Utilisation

Lancer le serveur depuis la racine du projet :

```bash
python3 src/back.py
```

Puis ouvrir <http://127.0.0.1:5000> dans un navigateur.

### API

`POST /api/generate` — JSON :

| Champ            | Valeurs                          | Description                          |
|------------------|----------------------------------|--------------------------------------|
| `message`        | hex string                       | Shellcode en hexadécimal             |
| `method`         | `A` \| `B`                       | A = remote, B = local                |
| `output`         | `EXE` \| `DLL`                   | Type de binaire cible                |
| `technique`      | `A` \| `B` \| `C` \| `D`         | Technique d'exécution                |
| `function_names` | liste séparée par virgules       | Noms des fonctions générées          |
| `target_process` | ex. `notepad.exe`                | Process cible (mode remote)          |

Réponse : archive ZIP contenant `loader.nim`.

### Compilation du loader

```bash
nim c -d:release --app:console loader.nim     # EXE
nim c -d:release --app:lib     loader.nim     # DLL
```

## Avertissement

Ce dépôt contient du code destiné à des travaux pratiques offensifs. Toute utilisation hors d'un cadre légal et autorisé est interdite.
