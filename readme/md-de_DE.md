# cpkg – Ein leichtgewichtiger C-Paketmanager

<div align="center">
  <img src="../image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![Lizenz](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Plattform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-2.0.0--beta-brightgreen.svg)
  ![Status](https://img.shields.io/badge/status-öffentliche%20Beta-brightgreen.svg)

**C-Bibliotheken einfach bauen, installieren und verwalten**
</div>

## Sprache
[English](../README.md) | [中文](md-zh_CN.md) | Deutsch

---

## Urheberrecht & Lizenz

Copyright (C) 2026 Lemonade-NingYou

Dieses Programm ist freie Software: Sie können es unter den Bedingungen der GNU General Public License, wie von der Free Software Foundation veröffentlicht, entweder Version 3 der Lizenz oder (nach Ihrer Wahl) jeder späteren Version, weiterverteilen und/oder modifizieren.

Dieses Programm wird in der Hoffnung verteilt, dass es nützlich sein wird, aber **ohne jede Gewährleistung**; selbst ohne die implizite Gewährleistung der Marktgängigkeit oder Eignung für einen bestimmten Zweck. Details finden Sie in der GNU General Public License.

Sie sollten eine Kopie der GNU General Public License zusammen mit diesem Programm erhalten haben. Falls nicht, besuchen Sie <https://www.gnu.org/licenses/>.

Der vollständige Lizenztext ist auch erhältlich unter:  
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

---

## 🎉 Ankündigung der öffentlichen Beta

Wir freuen uns, bekannt zu geben, dass **cpkg 2.0.0** nun in der **öffentlichen Beta** ist!

Alle Kernfunktionen sind vollständig implementiert und getestet:
- ✅ **Build** – Ihr C‑Projekt in eine einzelne `.cpl`-Datei packen
- ✅ **Install** – Pakete verifizieren und in Systemverzeichnisse installieren
- ✅ **Remove** – Pakete sauber anhand des Manifests deinstallieren
- ✅ **List** – Alle installierten Pakete mit Metadaten anzeigen

Das Werkzeug ist bereit für den Praxiseinsatz. Wir freuen uns über Feedback und Beiträge.

---

## Einführung

cpkg ist ein leichtgewichtiger C-Paketmanager, der das Paketieren, Installieren und Verwalten von C-Bibliotheken und Kopfdateien vereinfacht.

Dieses Repository enthält eine **vollständig überarbeitete** Version von cpkg mit modularer Architektur, Integritätsprüfung (SHA‑256), inkrementellen Builds und einem übersichtlichen Manifest-System.

### Freie-Software-Konformität

cpkg ist **Freie Software** unter der GPLv3. Alle Build- und Laufzeitabhängigkeiten sind ebenfalls Freie Software:

- `libyaml-dev` – MIT-Lizenz
- `libarchive-dev` – BSD‑2‑Clause-Lizenz
- `libssl-dev` – OpenSSL / Apache‑ähnliche Lizenz
- `libcjson-dev` – MIT-Lizenz

Wir sind bestrebt, sicherzustellen, dass cpkg frei bleibt und Ihre Freiheit respektiert.

## Funktionen

- **Build** – Erstellt aus einem Quellverzeichnis eine eigenständige `.cpl`-Datei.
- **Install** – Überprüft und installiert `.cpl`-Pakete in Systemverzeichnisse.
- **Remove** – Deinstalliert Pakete mithilfe des aufgezeichneten Manifests.
- **List** – Zeigt alle installierten Pakete mit Metadaten an.
- **Integrität** – SHA‑256-Hash schützt vor Beschädigung oder Manipulation.
- **Inkrementell** – Nur geänderte Dateien werden beim Bau kopiert (spart Zeit).
- **Sauber** – Löscht temporäre Dateien nach der Installation automatisch.
- **Manifest** – Speichert jede installierte Datei für spätere Deinstallation.

## Projektstatus

| Funktion       | Status                  |
|----------------|-------------------------|
| `build`        | ✅ Abgeschlossen        |
| `install`      | ✅ Abgeschlossen        |
| `remove`       | ✅ Abgeschlossen        |
| `list`         | ✅ Abgeschlossen        |

Alle Funktionen sind produktionsreif. Das Projekt befindet sich in der **öffentlichen Beta** – wir ermutigen zum Testen und Melden von Problemen.

## Erste Schritte

### Abhängigkeiten

```bash
sudo apt install libyaml-dev libarchive-dev libssl-dev libcjson-dev
```

### cpkg aus dem Quellcode erstellen

```bash
git clone https://github.com/Lemonade-NingYou/cpkg.git
cd cpkg
mkdir build && cd build
cmake ..
make
sudo make install
```

## Konfiguration (`config.txt`)

Die Konfigurationsdatei verwendet YAML. Ein ausführliches Beispiel und alle Felder sind im [englischen README](../README.md) beschrieben.

## Verwendung

### Paket bauen

```bash
cpkg -b /pfad/zum/projekt
```

Erzeugt `<PocketName>-<version>.cpl`.

### Paket installieren

```bash
sudo cpkg -i paketname.cpl
```

Installiert Bibliotheken und Header in die Systemverzeichnisse und erstellt ein Manifest unter `/var/cache/cpkg/<PocketName>.json`.

### Paket entfernen

```bash
sudo cpkg -r paketname
```

Liest das Manifest, löscht alle darin aufgeführten Dateien und entfernt die Manifestdatei selbst.

### Installierte Pakete auflisten

```bash
cpkg -l
```

Zeigt alle installierten Pakete mit Metadaten an.

Weitere Optionen:

```bash
cpkg -h   # Hilfe
cpkg -V   # Version
```

## Mitwirken

1. Fork des [cpkg GitHub-Repositorys](https://github.com/Lemonade-NingYou/cpkg).
2. Neuen Branch für Ihre Änderungen erstellen.
3. Änderungen vornehmen und gründlich testen.
4. Pull-Request an den Hauptzweig senden.

Für größere Änderungen bitten wir, zuerst ein Issue zu eröffnen.

## Kontakt

- Projektbetreuer: Lemonade-NingYou (über GitHub Issues oder E-Mail)
- Allgemeine Fragen zu Freiheit und Lizenzierung richten Sie bitte an die [Free Software Foundation](https://www.fsf.org/).

## Lizenz

cpkg ist unter der GPLv3-Lizenz lizenziert. Den vollständigen Text finden Sie in der Datei [COPYING](COPYING) oder unter <https://www.gnu.org/licenses/>.
```

---

以上三个文件已全部更新，可直接替换原有文件。如有其他定制要求（例如添加 FSF 徽章或特定的免责声明），请随时告知。